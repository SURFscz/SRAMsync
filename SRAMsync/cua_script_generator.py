"""
CUA implementation of the event_handler base class.

The CUA event handler generates a bash file that needs to be executed
manually after each sync in order to propagate all changes to the CUA.
The generated script makes use of the sara_usertool to interact with
the CUA.
"""

from datetime import datetime
import logging
import os
import stat
import subprocess

from jsonschema import ValidationError, validate

from SRAMsync.common import get_attribute_from_entry, render_templated_string
from SRAMsync.event_handler import EventHandler
from SRAMsync.sramlogger import logger
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
            "auxiliary_event_handler": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "config": {"type": "object"},
                },
                "required": ["name", "config"],
            },
        },
        "required": ["filename", "add_cmd", "modify_cmd", "check_cmd", "sshkey_cmd"],
    }

    # script_file_descriptor = None

    cua_group_types = {"system_group", "project_group"}

    def __init__(self, service, cfg, cfg_path, **args) -> None:
        super().__init__(service, cfg, cfg_path, args)

        try:
            validate(schema=CuaScriptGenerator._schema, instance=cfg)

            self.run = bool("run" in args)

            self.cfg = cfg
            self.script_name = render_templated_string(cfg["filename"], service=service)
            self.script_file_descriptor = open(  # pylint: disable=consider-using-with
                self.script_name, "w+", encoding="utf8"
            )
            os.chmod(self.script_name, stat.S_IRWXU | stat.S_IMODE(0o0744))
            self.service_name = service
            self.add_cmd = cfg["add_cmd"]
            self.modify_cmd = cfg["modify_cmd"]
            self.check_cmd = cfg["check_cmd"]
            self.sshkey_cmd = cfg["sshkey_cmd"]
            self._generate_header()
        except ConfigValidationError as e:
            raise e
        except ValidationError as e:
            raise ConfigValidationError(e, cfg_path) from e

    def __del__(self):
        if self.script_file_descriptor:
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

    def start_of_co_processing(self, co: str) -> None:
        """
        Print a useful message for the start_of_co_processing event. Call
        the auxiliary event class.
        """

        self._print(f"\n# service: {self.service_name}/{co}")

    def add_new_user(self, co: str, group: str, user: str, entry: dict) -> None:
        """
        Write the appropriate sara_usertools commands to the bash script for
        adding new users. Call the auxiliary event class.
        """

        givenname = get_attribute_from_entry(entry, "givenName")
        sn = get_attribute_from_entry(entry, "sn")
        mail = get_attribute_from_entry(entry, "mail")
        line = f"sram:{givenname}:{sn}:{user}:0:0:0:/bin/bash:0:0:{mail}:0123456789:zz:{group}"

        self._print(f"## Adding user: {user}")
        self._print(f"{self.check_cmd} {user} ||")
        self._print(
            f"  {{\n"
            f'    echo "{line}" | {self.add_cmd} -f-\n'
            f"    {self.modify_cmd} --service sram:{self.service_name} {user}\n"
            f"  }}\n"
        )

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

    def add_new_group(self, co: str, group: str, group_attributes: list) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new group. This is either a CUA system or project group as
        specified per configuration file. Call the auxiliary event class.
        """
        if "system_group" in group_attributes:
            self._add_new_system_group(group)
        elif "project_group" in group_attributes:
            self._add_new_project_group(group)
        else:
            logger.error("Could not determine group type (system_group or project_group) for {group}.")

    @staticmethod
    def _add_new_system_group(group: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new CUA system group. However, the current version of the
        sara_usertool do not support this and hence a warning message is
        displayed instead.
        """
        logger.warning("Ignoring adding system group %s. It should be done by the CUA team.", group)

    def _add_new_project_group(self, group: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new CUA project group.
        """
        line = f"sram_group:description:dummy:{group}:0:0:0:/bin/bash:0:0:dummy:dummy:dummy:"

        self._print(f"## Adding group: {group}")
        self._print(f"{self.check_cmd} {group} ||")
        self._print(f"  {{\n    echo '{line}' | {self.add_cmd} -f-\n  }}\n")

    def remove_group(self, co: str, group: str, group_attributes: list):
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a new CUA project group. Call the auxiliary event class.
        """
        self._print(f"# Removing group {group}")
        self._print(f"{self.add_cmd} --remove {group}")

    def add_user_to_group(self, co: str, group: str, group_attributes: list, user: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a user to a group. Call the auxiliary event class.
        """
        self._print(f"# Add {user} to group {group}")
        self._update_user_in_group(group, group_attributes, user, add=True)

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
        self._update_user_in_group(group, group_attributes, user, add=False)

    def remove_graced_user_from_group(self, co: str, group: str, group_attributes: list, user: str):
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a user from a graced group. Call the auxiliary event class.
        """
        self._print(f"# Grace time has ended for user {user} from group {group}")
        self.remove_user_from_group(co, group, group_attributes, user)

    def _update_user_in_group(self, group: str, group_attributes: list, user: str, add: bool) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        updating users in a graced group. Call the auxiliary event class.
        """
        attr = set(group_attributes)
        number_of_attributes = len(attr)
        length2 = len(attr - self.cua_group_types)

        if add:
            remove = " "
        else:
            remove = " --remove "

        if number_of_attributes - length2 == 1:
            if "system_group" in attr:
                self._print(f"{self.modify_cmd}{remove}--access {self.service_name} {group} {user}\n")

            if "project_group" in attr:
                self._print(f"{self.modify_cmd}{remove}--group {group} {user}\n")
        elif number_of_attributes - length2 == 0:
            error = f"Expecting one the following attributes {self.cua_group_types} for {group}."
            raise ValueError(error)
        else:
            error = (
                f'\'{", ".join(self.cua_group_types)}\' are mutually exclusive in the attributes '
                f"of group: {group}."
            )
            raise ValueError(error)

    def finalize(self) -> None:
        """
        Close the generated script with final bash command. This includes for example
        replacing the status file with the provisional one.
        """
        if "provisional_status_filename" in self.cfg:
            service = self.service_name
            status_filename = self.cfg["status_filename"]
            status_filename = render_templated_string(status_filename, service=service)
            provisional_status_filename = self.cfg["provisional_status_filename"]
            provisional_status_filename = render_templated_string(
                provisional_status_filename, service=service
            )

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
