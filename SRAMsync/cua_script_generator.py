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
from datetime import datetime, timedelta
import sys
from typing import Any, Callable, Literal, Pattern, Union, cast
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError, validate

from SRAMsync.common import get_attribute_from_entry, render_templated_string
from SRAMsync.event_handler import EventHandler
from SRAMsync.json_file import JsonFile
from SRAMsync.sramlogger import logger
from SRAMsync.sync_with_sram import ConfigValidationError
from SRAMsync.typing import CuaNotificationsConfig, EventHandlerConfig


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

    cua_group_types: set[str] = {"system_group", "project_group"}

    def __init__(self, service: str, cfg: EventHandlerConfig, state: JsonFile, cfg_path: Path) -> None:
        super().__init__(service, cfg, state, cfg_path)

        try:
            validate(
                schema=CuaScriptGenerator._schema,
                instance=cfg["event_handler_config"],
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )

            self.run = False
            self.org_co_uuids = cast(dict[str, str], {})

            self.cfg = cast(CuaNotificationsConfig, cfg["event_handler_config"])
            self.state = state
            self.script_name = render_templated_string(template_string=self.cfg["filename"], service=service)
            self.script_file_descriptor = open(file=self.script_name, mode="w+", encoding="utf8")
            os.chmod(path=self.script_name, mode=stat.S_IRWXU)
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
            raise ConfigValidationError(exception=e, path=cfg_path) from e

    def __del__(self) -> None:
        if hasattr(self, "script_file_descriptor"):
            self.script_file_descriptor.close()

    def _generate_header(self) -> None:
        """Generate an explanatory header in the generated script."""

        self._print(string="#!/usr/bin/env bash\n")
        self._print(string="#" * 80)
        self._print(string="#")
        self._print(string="#  Automatically generated script by cua-sync")
        self._print(string=f"#  Date: {datetime.now()}")
        self._print(string="#")
        self._print(string="#  By executing this script, the CUA is synchronized with the state in SRAM")
        self._print(string="#  at the time this script has been generated. The service this script was")
        self._print(string=f"#  generated for is: {self.service_name}")
        self._print(string="#")
        self._print(string="#  This script looses its purpose after running it and a new one must be")
        self._print(string=f"#  generated to sync future changes in the COs for {self.service_name}.")
        self._print(string="#")
        self._print(string="#  The script might be empty, in which case there was nothing to be synced.")
        self._print(string="#")
        self._print(string="#" * 80)
        self._print(string="")
        self._print(string="trap quit INT")
        self._print(string="")
        self._print(string="function quit() {")
        self._print(string="  echo 'quitting'")
        self._print(string="  exit")
        self._print(string="}")
        self._print(string="")

    def _print(self, string: str) -> None:
        """Helper function for printing strings to a file."""
        print(string, file=self.script_file_descriptor)

    def get_supported_arguments(
        self,
    ) -> dict[str, dict[str, Union[Union[Callable[[str], None], Callable[[], None]], str]]]:
        """
        Process the arguments that are passed on the command line for plugins.
        Note that not all supplied arguments are necessary supplied for a specific
        module. All plugins are passed the same list of arguments and thus a module
        can encounter an argument that is not for this module and thus must be ignored.
        An unknown argument does not mean that it is an error.
        """
        options: dict[str, dict[str, Union[Union[Callable[[str], None], Callable[[], None]], str]]] = {
            "run": {"action": lambda: setattr(self, "run", True), "type": "bool"},
        }

        return options

    def process_co_attributes(self, attributes: dict[str, list[bytes]], org: str, co: str) -> None:
        """Process the CO attributes."""
        super().process_co_attributes(attributes, org, co)

    def start_of_co_processing(self, co: str) -> None:
        """
        Print a useful message for the start_of_co_processing event. Call
        the auxiliary event class.
        """

        self._print(string=f"\n# service: {self.service_name}/{co}")

    def add_new_user(self, entry: dict[str, list[bytes]], **kwargs: Any) -> None:
        """
        Write the appropriate sara_usertools commands to the bash script for
        adding new users. Call the auxiliary event class.
        """

        try:
            # org = kwargs["org"]
            co = kwargs["co"]
            groups = kwargs["groups"]
            group_attributes = kwargs["group_attributes"]
            org = kwargs["org"]
            user = kwargs["user"]
        except KeyError as e:
            logger.error("Missing(cua_script_generator) argument: %s", e)
            sys.exit(1)

        givenname: str = get_attribute_from_entry(entry, attribute="givenName")
        sn: str = get_attribute_from_entry(entry, attribute="sn")
        mail: str = get_attribute_from_entry(entry, attribute="mail")
        uniqueid: str = get_attribute_from_entry(entry, attribute="eduPersonUniqueId")
        group: str = ",".join(groups)

        command_args: dict[str, dict[str, str]] = dict()
        command_args[user] = dict()
        command_args[user]["template"] = "sram"
        command_args[user]["firstname"] = givenname
        command_args[user]["lastname"] = sn
        command_args[user]["email"] = mail
        command_args[user]["sgroups"] = group
        command_args[user]["sram_co"] = co
        command_args[user]["sram_id"] = uniqueid
        command_args[user]["sram_org"] = org

        if self.org_co_uuids:
            command_args[user]["sram_co_uuid"] = self.org_co_uuids[f"{org}-{co}"]

        command_json: str = json.dumps(command_args)

        self._print(string=f"## Adding user: {user}")
        self._print(string=f"{self.check_cmd} {user} ||")
        self._print(
            string=f"  {{\n" f"    echo '{command_json}' | {self.add_cmd} --file=- --format=json\n" f"  }}\n"
        )

        self._handle_extra_groups(groups, user, group_attributes)

    def add_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a user's public SSH key. Call the auxiliary event class.
        """
        self._print(string=f"### SSH Public key: {key[:30]}...{key[-40:]}")
        self._print(string=f'{self.sshkey_cmd} "{key}" {user}\n')

    def delete_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        deleting a user's public SSH key. Call the auxiliary event class.
        """
        self._print(string=f"### Remove SSH Public key: {key}")
        self._print(string=f'{self.sshkey_cmd} "{key}" --remove {user}\n')

    def add_new_groups(self, co: str, groups: list[str], group_attributes: list[str]) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new group. This is either a CUA system, project or an
        extra_groups group as specified per configuration file.
        """
        if "system_group" in group_attributes:
            re_extra_groups_attribute: Pattern[str] = re.compile(
                "^extra_groups *= *[a-zA-Z0-9_-]+ *(, *?[a-z]+)*[, ]*$"
            )

            extra_groups: list[str] = [
                item.strip()
                for attribute in group_attributes
                if re_extra_groups_attribute.match(attribute)
                for item in attribute.split(sep="=")[1].split(sep=",")
            ]

            groups = list(set(groups) - set(extra_groups))

            self._add_new_system_groups(groups)
            if extra_groups:
                self._add_new_project_groups(groups=extra_groups)

        elif "project_group" in group_attributes:
            self._add_new_project_groups(groups)
        else:
            logger.error(
                "Could not determine group type (system_group or project_group) for %s.",
                groups,
            )

    @staticmethod
    def _add_new_system_groups(groups: list[str]) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new CUA system group. However, the current version of the
        sara_usertool does not support this. Instead of a warning message, a
        debug message is displayed, as this is expected behaviour for the CUA.
        """
        group_names: str = ", ".join(groups)
        plural: Literal["s", ""] = "s" if len(groups) > 1 else ""
        logger.debug(
            "Ignoring adding system group%s %s. It should be done by the CUA team.",
            plural,
            group_names,
        )

    def _add_new_project_groups(self, groups: list[str]) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new CUA project group.
        """
        for group in groups:
            command_args: dict[str, dict[str, str]] = dict()
            command_args[group] = dict()
            command_args[group]["template"] = "sram_group"
            command_args[group]["firstname"] = "sram_group"

            command_args_json: str = json.dumps(obj=command_args)

            self._print(string=f"## Adding group: {group}")
            self._print(string=f"{self.check_cmd} {group} ||")
            self._print(
                string=f"  {{\n    echo '{command_args_json}' | {self.add_cmd} --format=json --file=-\n  }}\n"
            )

    def remove_group(self, co: str, group: str, group_attributes: list[str]):
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a new CUA project group. Call the auxiliary event class.
        """
        self._print(string=f"# Removing group(s) {group}")
        self._print(string=f"{self.add_cmd} --remove-group {group}")

    def add_user_to_group(self, **kwargs: Any) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a user to a group. Call the auxiliary event class.
        """
        try:
            # co = kwargs["co"]
            groups = kwargs["groups"]
            group_attributes = kwargs["group_attributes"]
            user = kwargs["user"]
        except KeyError as e:
            logger.error("Missing(cua_script_generator) argument: %s", e)
            sys.exit(1)

        self._print(string=f"# Add {user} to group(s) {groups}")
        self._update_user_in_groups(groups, group_attributes, user, add=True)

    def start_grace_period_for_user(
        self, co: str, group: str, group_attributes: list[str], user: str, duration: timedelta
    ) -> None:
        """
        The grace period for user user has started. However, for the CUA this
        has no implications. Until the grace period has ended, nothing will change
        for the CUA.
        """

    def remove_user_from_group(self, co: str, group: str, group_attributes: list[str], user: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a user from a group. Call the auxiliary event class.
        """
        self._print(string=f"# Remove {user} from group {group}")
        self._update_user_in_groups([group], group_attributes, user, add=False)

    def remove_graced_user_from_group(
        self, co: str, group: str, group_attributes: list[str], user: str
    ) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a user from a graced group. Call the auxiliary event class.
        """
        self._print(string=f"# Grace time has ended for user {user} from group {group}")
        self.remove_user_from_group(co, group, group_attributes, user)

    def _update_user_in_groups(
        self, groups: list[str], group_attributes: list[str], user: str, add: bool
    ) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        updating users in a graced group. Call the auxiliary event class.
        """

        comma_separated_groups: str = ",".join(groups)
        attr: set[str] = set(group_attributes)
        number_of_attributes: int = len(attr)
        length: int = len(attr - self.cua_group_types)

        if add:
            remove = " "
        else:
            remove = " --remove "

        if number_of_attributes - length == 1:
            if "system_group" in attr:
                self._print(
                    string=f"{self.modify_cmd}{remove}--access {self.service_name} {comma_separated_groups} {user}\n"
                )

            if "project_group" in attr:
                self._print(string=f"{self.modify_cmd}{remove}--group {comma_separated_groups} {user}\n")

            self._handle_extra_groups(groups, user, group_attributes)

        elif number_of_attributes - length == 0:
            error: str = (
                f"Expecting one the following attributes {self.cua_group_types} for {comma_separated_groups}."
            )
            raise ValueError(error)
        else:
            error = (
                f'\'{", ".join(self.cua_group_types)}\' are mutually exclusive in the attributes '
                f"of group: {groups}."
            )
            raise ValueError(error)

    def _handle_extra_groups(self, groups: list[str], user: str, group_attributes: list[str]) -> None:
        """
        Handle possible extra_groups attributes.
        """
        extra_groups: list[str] = [k.strip() for k in group_attributes if self.extra_groups_re.match(k)]
        if len(extra_groups) > 0:
            extra_groups = [k.split(sep="=")[1].split(sep=",") for k in extra_groups][0]
            extra_groups = [k.strip() for k in extra_groups]

            for extra_group in extra_groups:
                self._print(string=f"{self.modify_cmd} --group {extra_group} {user}")

    def finalize(self) -> None:
        """
        Close the generated script with final bash command. This includes for example
        replacing the status file with the provisional one.
        """
        if type(self.state).__name__ == "JsonFile":
            provisional_filename: Union[str, None] = self.state.get_provisional_status_filename()
            if provisional_filename:
                service: str = self.service_name
                status_filename: str = self.state.get_status_filename()
                status_filename = render_templated_string(template_string=status_filename, service=service)
                provisional_status_filename = render_templated_string(
                    template_string=provisional_filename, service=service
                )

                self._print(string="\n" + "#" * 32)
                self._print(string="# Cleaning provisional status. #")
                self._print(string="#" * 32)
                self._print(string=f'if [ -f "{provisional_status_filename}" ]; then')
                self._print(string=f'  mv "{provisional_status_filename}" "{status_filename}"')
                self._print(string="else")
                self._print(
                    string=f"  echo 'Cannot find {provisional_status_filename}. Has this script been run before?'"
                )
                self._print(string="fi")

        self._print(string="\n" + "#" * 43)
        self._print(string="#" + " " * 41 + "#")
        self._print(string="#  Script generation ended successfully.  #")
        self._print(string="#" + " " * 41 + "#")
        self._print(string="#" * 43)

        if self.run:
            logger.info("Executing generated script")
            self.script_file_descriptor.flush()
            try:
                result: subprocess.CompletedProcess[bytes] = subprocess.run(
                    [self.script_name], check=True, capture_output=True, shell=True
                )
                logger.debug("script retuned: %d", result.returncode)
                logger.debug("script output: %s", result.stdout)
            except subprocess.TimeoutExpired:
                logger.error("Script execution has been aborted. It took too long for the script to finish.")
            except subprocess.CalledProcessError as e:
                logger.error(
                    "Something went wrong during the execution of the generated script. "
                    "The following error was reported:"
                )
                logger.error(
                    "Command '%s' returned non-zero exit status %d.",
                    e.cmd[0],
                    e.returncode,
                )
            logger.info("Finished script execution")
