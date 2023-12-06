"""
CUA implementation of the event_handler base class.

The CUA event handler generates a bash file that needs to be executed
manually after each sync in order to propagate all changes to the CUA.
The generated script makes use of the sara_usertool to interact with
the CUA.
"""

import json
import os
import re
import stat
import subprocess
from datetime import datetime
from typing import Dict, List

from jsonschema import Draft202012Validator, ValidationError, validate

from SRAMsync.common import get_attribute_from_entry, render_templated_string
from SRAMsync.event_handler import EventHandler
from SRAMsync.sramlogger import logger
from SRAMsync.state import State
from SRAMsync.sync_with_sram import ConfigValidationError


class CuaScriptGenerator(EventHandler):
    """
    This class generates a bash script containing all necessary sara_usertool
    commands in order to get the state of the CUA synchronized with the SRAM
    LDAP.
    """

    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "filename": {"type": "string"},
            "add_cmd": {"type": "string"},
            "modify_cmd": {"type": "string"},
            "check_cmd": {"type": "string"},
            "ssh_cmd": {"type": "string"},
        },
        "required": ["filename", "add_cmd", "modify_cmd", "check_cmd", "sshkey_cmd"],
    }

    cua_group_types = {"system_group", "project_group"}

    def __init__(self, service: str, cfg: Dict, state: State, cfg_path: List[str]):
        super().__init__(service, cfg, state, cfg_path)

        try:
            validate(
                schema=CuaScriptGenerator._schema,
                instance=cfg["event_handler_config"],
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )

            self.run = False
            self._cba_co_budget_mapping_filename = ""

            self.cfg = cfg["event_handler_config"]
            self.state = state
            self.script_name = render_templated_string(self.cfg["filename"], service=service)
            self.script_file_descriptor = open(  # pylint: disable=consider-using-with
                self.script_name, "w+", encoding="utf8"
            )
            os.chmod(self.script_name, stat.S_IRWXU | stat.S_IMODE(0o0744))
            self.service_name = service
            self.add_cmd = self.cfg["add_cmd"]
            self.modify_cmd = self.cfg["modify_cmd"]
            self.check_cmd = self.cfg["check_cmd"]
            self.sshkey_cmd = self.cfg["sshkey_cmd"]
            self.extra_groups_re = re.compile("^[ \t]*extra_groups[ \t]*=[ \t]*([a-zA-Z0-9_\\-, \t]*)[ \t]*$")

            self._generate_header()
        except ConfigValidationError as e:
            raise e
        except ValidationError as e:
            raise ConfigValidationError(e, cfg_path) from e

    def __del__(self):
        if hasattr(self, "script_file_descriptor"):
            self.script_file_descriptor.close()

    def _generate_header(self) -> None:
        """Generate an explanatory header in the generated script."""

        self._print("#!/usr/bin/env bash\n")
        self._print("#" * 80)
        self._print("#")
        self._print("#  Automatically generated script by cua-sync")
        self._print(f"#  Date: {datetime.now()}")
        self._print("#")
        self._print("#  By executing this script, the CUA is synchronized with the state in SRAM")
        self._print("#  at the time this script has been generated. The service this script was")
        self._print(f"#  generated for is: {self.service_name}")
        self._print("#")
        self._print("#  This script looses its purpose after running it and a new one must be")
        self._print(f"#  generated to sync future changes in the COs for {self.service_name}.")
        self._print("#")
        self._print("#  The script might be empty, in which case there was nothing to be synced.")
        self._print("#")
        self._print("#" * 80)
        self._print("")
        self._print("trap quit INT")
        self._print("")
        self._print("function quit() {")
        self._print("  echo 'quitting'")
        self._print("  exit")
        self._print("}")
        self._print("")

    def _print(self, string: str):
        """Helper function for printing strings to a file."""
        print(string, file=self.script_file_descriptor)

    def get_supported_arguments(self):
        """
        Process the arguments that are passed on the command line for plugins.
        Note that not all supplied arguments are necessary supplied for a specific
        module. All plugins are passed the same list of arguments and thus a module
        can encounter an argument that is not for this module and thus must be ignored.
        An unknown argument does not mean that it is an error.
        """
        options = {
            "run": {"action": lambda: setattr(self, "run", True), "type": "bool"},
            "cba-co-budget-mapping-filename": {
                "action": self.handle_cba_co_budget_mapping_filename,
                "type": "path",
                "deprecated": "cba-co-budget-mapping-filename is depricated in v4.3.0 and will be removed in v4.4.0",
            },
        }

        return options

    def handle_cba_co_budget_mapping_filename(self, value):
        """Assign a value to self._cba_co_budget_mapping_filename"""
        self._cba_co_budget_mapping_filename = value

    def process_co_attributes(self, attributes: Dict[str, str], org: str, co: str) -> None:
        """Process the CO attributes."""
        co_uuid = attributes["uniqueIdentifier"][0].decode("utf-8")  # type: ignore

        try:
            with open(self._cba_co_budget_mapping_filename, "r") as fd:
                mappings = json.load(fd)

            mapping_updated = False
            new_mappings = {}
            for uuid, dict_values in mappings.items():
                if uuid != co_uuid and mappings[uuid]["org"] == org and mappings[uuid]["co"] == co:
                    new_mappings[co_uuid] = dict_values
                    mapping_updated = True
                else:
                    new_mappings[uuid] = dict_values

            if mapping_updated:
                with open(self._cba_co_budget_mapping_filename, "w") as fd:
                    json.dump(new_mappings, fd)
        except FileNotFoundError:
            logger.warn(
                "CuaScriptGenerator: CBA CO budget mapping per file has been requested, however file '%s' does not exists.",
                self._cba_co_budget_mapping_filename,
            )

        return super().process_co_attributes(attributes, org, co)

    def start_of_co_processing(self, co: str) -> None:
        """
        Print a useful message for the start_of_co_processing event. Call
        the auxiliary event class.
        """

        self._print(f"\n# service: {self.service_name}/{co}")

    def add_new_user(
        self,
        co: str,
        groups: List[str],
        user: str,
        group_attributes: List[str],
        entry: Dict[str, List[bytes]],
    ) -> None:
        """
        Write the appropriate sara_usertools commands to the bash script for
        adding new users. Call the auxiliary event class.
        """

        givenname = get_attribute_from_entry(entry, "givenName")
        sn = get_attribute_from_entry(entry, "sn")
        mail = get_attribute_from_entry(entry, "mail")
        group = ",".join(groups)

        d = dict()
        d[user] = dict()
        d[user]['template'] = 'sram'
        d[user]['firstname'] = givenname
        d[user]['lastname'] = sn
        d[user]['email'] = mail
        d[user]['sgroups'] = group

        json_str = json.dumps(d)

        self._print(f"## Adding user: {user}")
        self._print(f"{self.check_cmd} {user} ||")
        self._print(
            f"  {{\n"
            f"    echo '{json_str}' | {self.add_cmd} --file=- --format=json\n"
            f"  }}\n"
        )

        self._handle_extra_groups(groups, user, group_attributes)

    def add_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a user's public SSH key. Call the auxiliary event class.
        """
        self._print(f"### SSH Public key: {key[:30]}...{key[-40:]}")
        self._print(f'{self.sshkey_cmd} "{key}" {user}\n')

    def delete_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        deleting a user's public SSH key. Call the auxiliary event class.
        """
        self._print(f"### Remove SSH Public key: {key}")
        self._print(f'{self.sshkey_cmd} --remove "{key}" {user}\n')

    def add_new_groups(self, co: str, groups: List[str], group_attributes: list) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new group. This is either a CUA system, project or an
        extra_groups group as specified per configuration file.
        """
        if "system_group" in group_attributes:
            re_extra_groups_attribute = re.compile("^extra_groups *= *[a-zA-Z0-9_-]+ *(, *?[a-z]+)*[, ]*$")

            extra_groups = [
                item.strip()
                for attribute in group_attributes
                if re_extra_groups_attribute.match(attribute)
                for item in attribute.split("=")[1].split(",")
            ]

            groups = list(set(groups) - set(extra_groups))

            self._add_new_system_groups(groups)
            if extra_groups:
                self._add_new_project_groups(extra_groups)

        elif "project_group" in group_attributes:
            self._add_new_project_groups(groups)
        else:
            logger.error("Could not determine group type (system_group or project_group) for %s.", groups)

    @staticmethod
    def _add_new_system_groups(groups: List[str]) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new CUA system group. However, the current version of the
        sara_usertool does not support this. Instead of a warning message, a
        debug message is displayed, as this is expected behaviour for the CUA.
        """
        group_names = ", ".join(groups)
        plural = "s" if len(groups) > 1 else ""
        logger.debug(
            "Ignoring adding system group%s %s. It should be done by the CUA team.", plural, group_names
        )

    def _add_new_project_groups(self, groups: List[str]) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new CUA project group.
        """
        for group in groups:
            line = f"sram_group:sram_group:dummy:{group}:0:0:0:/bin/bash:0:0:no-reply@surf.nl:::"
            self._print(f"## Adding group: {group}")
            self._print(f"{self.check_cmd} {group} ||")
            self._print(f"  {{\n    echo '{line}' | {self.add_cmd} -f-\n  }}\n")

    def remove_group(self, co: str, group: str, group_attributes: list):
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a new CUA project group. Call the auxiliary event class.
        """
        self._print(f"# Removing group(s) {group}")
        self._print(f"{self.add_cmd} --remove-group {group}")

    def add_user_to_group(self, co: str, groups: List[str], group_attributes: List[str], user: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a user to a group. Call the auxiliary event class.
        """
        self._print(f"# Add {user} to group(s) {groups}")
        self._update_user_in_groups(groups, group_attributes, user, add=True)

    def start_grace_period_for_user(self, co, group, group_attributes, user, duration):
        """
        The grace period for user user has started. However, for the CUA this
        has no implications. Until the grace period has ended, nothing will change
        for the CUA.
        """

    def remove_user_from_group(self, co: str, group: str, group_attributes: list, user: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a user from a group. Call the auxiliary event class.
        """
        self._print(f"# Remove {user} from group {group}")
        self._update_user_in_groups([group], group_attributes, user, add=False)

    def remove_graced_user_from_group(self, co: str, group: str, group_attributes: list, user: str):
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a user from a graced group. Call the auxiliary event class.
        """
        self._print(f"# Grace time has ended for user {user} from group {group}")
        self.remove_user_from_group(co, group, group_attributes, user)

    def _update_user_in_groups(
        self, groups: List[str], group_attributes: List[str], user: str, add: bool
    ) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        updating users in a graced group. Call the auxiliary event class.
        """

        comma_separated_groups = ",".join(groups)
        attr = set(group_attributes)
        number_of_attributes = len(attr)
        length = len(attr - self.cua_group_types)

        if add:
            remove = " "
        else:
            remove = " --remove "

        if number_of_attributes - length == 1:
            if "system_group" in attr:
                self._print(
                    f"{self.modify_cmd}{remove}--access {self.service_name} {comma_separated_groups} {user}\n"
                )

            if "project_group" in attr:
                self._print(f"{self.modify_cmd}{remove}--group {comma_separated_groups} {user}\n")

            self._handle_extra_groups(groups, user, group_attributes)

        elif number_of_attributes - length == 0:
            error = (
                f"Expecting one the following attributes {self.cua_group_types} for {comma_separated_groups}."
            )
            raise ValueError(error)
        else:
            error = (
                f'\'{", ".join(self.cua_group_types)}\' are mutually exclusive in the attributes '
                f"of group: {groups}."
            )
            raise ValueError(error)

    def _handle_extra_groups(self, groups: List[str], user: str, group_attributes: List[str]) -> None:
        """
        Handle possible extra_groups attributes.
        """
        extra_groups = [k.strip() for k in group_attributes if self.extra_groups_re.match(k)]
        if len(extra_groups) > 0:
            extra_groups = [k.split("=")[1].split(",") for k in extra_groups][0]
            extra_groups = [k.strip() for k in extra_groups]

            for extra_group in extra_groups:
                self._print(f"{self.modify_cmd} --group {extra_group} {user}")

    def finalize(self) -> None:
        """
        Close the generated script with final bash command. This includes for example
        replacing the status file with the provisional one.
        """
        if type(self.state).__name__ == "JsonFile":
            provisional_filename = self.state.get_provisional_status_filename()
            if provisional_filename:
                service = self.service_name
                status_filename = self.state.get_status_filename()
                status_filename = render_templated_string(status_filename, service=service)
                provisional_status_filename = render_templated_string(provisional_filename, service=service)

                self._print("\n" + "#" * 32)
                self._print("# Cleaning provisional status. #")
                self._print("#" * 32)
                self._print(f'if [ -f "{provisional_status_filename}" ]; then')
                self._print(f'  mv "{provisional_status_filename}" "{status_filename}"')
                self._print("else")
                self._print(
                    f"  echo 'Cannot find {provisional_status_filename}. Has this script been run before?'"
                )
                self._print("fi")

        self._print("\n" + "#" * 43)
        self._print("#" + " " * 41 + "#")
        self._print("#  Script generation ended successfully.  #")
        self._print("#" + " " * 41 + "#")
        self._print("#" * 43)

        if self.run:
            logger.info("Executing generated script")
            self.script_file_descriptor.flush()
            try:
                result = subprocess.run([self.script_name], check=True, capture_output=True, shell=True)
                logger.debug("script retuned: %d", result.returncode)
                logger.debug("script output: %s", result.stdout)
            except subprocess.TimeoutExpired:
                logger.error("Script execution has been aborted. It took too long for the script to finish.")
            except subprocess.CalledProcessError as e:
                logger.error(
                    "Something went wrong during the execution of the generated script. "
                    "The following error was reported:"
                )
                logger.error("Command '%s' returned non-zero exit status %d.", e.cmd[0], e.returncode)
            logger.info("Finished script execution")
