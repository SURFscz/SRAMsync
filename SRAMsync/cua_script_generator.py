"""
CUA implementation of the event_handler base class.

The CUA event handler generates a bash file that needs to be executed
manually after each sync in order to propagate all changes to the CUA.
The generated script makes use of the sara_usertool to interact with
the CUA.
"""

import importlib
from datetime import datetime
from jsonschema import validate, ValidationError

from .sync_with_sram import ConfigValidationError
from .common import pascal_case_to_snake_case, render_templated_string
from .sramlogger import logger
from .event_handler import EventHandler
from .dummy_event_handler import DummyEventHandler


class CuaScriptGenerator(EventHandler):
    """
    This class genertates a bash script containing all necessary sara_usertool
    commands in order to get the state of the CUA synchronized with the SRAM
    LDAP.
    """

    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "filename": {"type": "string"},
            "add_user_cmd": {"type": "string"},
            "modify_user_cmd": {"type": "string"},
            "auxiliary_event_handler": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "config": {"type": "object"},
                },
                "required": ["name", "config"],
            },
        },
        "required": ["filename", "add_user_cmd", "modify_user_cmd"],
        "optional": ["auxiliary_event_handler"],
    }

    script_file_descriptor = None

    cua_group_types = {"system_group", "project_group"}

    def __init__(self, service, cfg, cfg_path):
        super().__init__(service, cfg, cfg_path)

        try:
            validate(schema=CuaScriptGenerator._schema, instance=cfg)

            if "auxiliary_event_handler" in cfg:
                cfg_path.append("auxiliary_event_handler")

                auxiliary_config = {}
                if "secrets" in cfg:
                    auxiliary_config["secrets"] = cfg["secrets"]
                auxiliary_config.update(cfg["auxiliary_event_handler"]["config"])

                self.notify = self.get_auxiliary_notificaion_instance(
                    cfg["auxiliary_event_handler"]["name"],
                    auxiliary_config,
                    service,
                    cfg_path,
                )
            else:
                self.notify = DummyEventHandler(service, cfg, cfg_path)

            self.cfg = cfg
            script_name = render_templated_string(cfg["filename"], service=service)
            self.script_file_descriptor = open(script_name, "w+")
            self.add_user_cmd = cfg["add_user_cmd"]
            self.modify_user_cmd = cfg["modify_user_cmd"]
            self.service_name = service
            self.generate_header()
        except ConfigValidationError as e:
            raise e
        except ValidationError as e:
            raise ConfigValidationError(e, cfg_path) from e

    def __del__(self):
        if self.script_file_descriptor:
            self.script_file_descriptor.close()

    @staticmethod
    def get_auxiliary_notificaion_instance(
        event_handler_class_name: str, cfg: dict, service: str, cfg_path: str
    ) -> EventHandler:
        """Load the auxiliary event handler class."""

        event_handler_module_name = pascal_case_to_snake_case(event_handler_class_name)
        event_handler_module = importlib.import_module(f"SRAMsync.{event_handler_module_name}")
        event_handler_class = getattr(event_handler_module, event_handler_class_name)

        return event_handler_class(service, cfg, cfg_path)

    def generate_header(self) -> None:
        """Generate an explanatory header in the generated script."""

        self.print("#" * 80)
        self.print("#")
        self.print("#  Automatically generated script by cua-sync")
        self.print(f"#  Date: {datetime.now()}")
        self.print("#")
        self.print("#  By executing this script, the CUA is synchronized with the state in SRAM")
        self.print("#  at the time this script has been generated. The service this script was")
        self.print(f"#  generated for is: {self.service_name}")
        self.print("#")
        self.print("#  This script looses its purpuse after running it and a new one must be")
        self.print(f"#  generated to sync future changes in the COs for {self.service_name}.")
        self.print("#")
        self.print("#  The script might be empty, in which case there was nothing to be synced.")
        self.print("#")
        self.print("#" * 80)
        self.print("")
        self.print("set -o xtrace")
        self.print("")
        self.print("trap quit INT")
        self.print("")
        self.print("function quit() {")
        self.print("  echo 'quiting'")
        self.print("  exit")
        self.print("}")
        self.print("")

    def print(self, string):
        """Helper function for printing strings to a file."""
        print(string, file=self.script_file_descriptor)

    def start_of_co_processing(self, co: str) -> None:
        """
        Print a useful message for the start_of_co_processing event. Call
        the auxiliary event class.
        """

        self.print(f"\n# service: {self.service_name}/{co}")
        self.notify.start_of_co_processing(co)

    def add_new_user(self, co: str, group: str, givenname: str, sn: str, user: str, mail: str) -> None:
        """
        Write the appropriate sara_usertools commands to the bash script for
        adding new users. Call the auxiliary event class.
        """

        line = f"sram:{givenname}:{sn}:{user}:0:0:0:/bin/bash:0:0:{mail}:0123456789:zz:{group}"

        self.print(f"## Adding user: {user}")
        self.print(f"{self.modify_user_cmd} --list {user} ||")
        self.print(
            f"  {{\n"
            f'    echo "{line}" | {self.add_user_cmd} -f-\n'
            f"    {self.modify_user_cmd} --service sram:{self.service_name} {user}\n"
            f"  }}\n"
        )

        self.notify.add_new_user(co, group, givenname, sn, user, mail)

    def add_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a user's public SSH key. Call the auxiliary event class.
        """
        self.print(f"### SSH Public key: {key[:30]}...{key[-40:]}")
        self.print(f'{self.modify_user_cmd} --ssh-public-key "{key}" {user}\n')

        self.notify.add_public_ssh_key(co, user, key)

    def delete_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding deleting user's public SSH key. Call the auxiliary event class.
        """
        self.print(f"### Remove SSH Public key: {key}")
        self.print(f'{self.modify_user_cmd} -r --ssh-public-key "{key}" {user}\n')

        self.notify.delete_public_ssh_key(co, user, key)

    def add_new_group(self, co: str, group: str, group_attributes: list) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new group. This is either a CUA system or project group as
        specified per configuration file. Call the auxiliary event class.
        """
        if "system_group" in group_attributes:
            self.add_new_system_group(group)
        elif "project_group" in group_attributes:
            self.add_new_project_group(group)
        else:
            logger.error("Could not determine group type (system_group or project_group) for {group}.")

        self.notify.add_new_group(co, group, group_attributes)

    @staticmethod
    def add_new_system_group(group: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new CUA system group. However, the current version of the
        sara_usertool do not support this and hence a warning message is
        displayed instead.
        """
        logger.warning(f"Ignoring adding system group {group}. It should be done by the CUA team.")

    def add_new_project_group(self, group: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a new CUA project group.
        """
        line = f"sram_group:description:dummy:{group}:0:0:0:/bin/bash:0:0:dummy:dummy:dummy:"

        self.print(f"## Adding group: {group}")
        self.print(f"{self.modify_user_cmd} --list {group} ||")
        self.print(f'  {{\n    echo "{line}" | {self.add_user_cmd} -f-\n  }}\n')

    def remove_group(self, co: str, group: str, group_attributes: list):
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a new CUA project group. Call the auxiliary event class.
        """
        self.print("#!!! Remove group")

        self.notify.remove_group(co, group, group_attributes)

    def add_user_to_group(self, co: str, group: str, group_attributes: list, user: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        adding a user to a group. Call the auxiliary event class.
        """
        self.print(f"# Add {user} to group {group}")
        self.update_user_in_group(group, group_attributes, user, add=True)

        self.notify.add_user_to_group(co, group, group_attributes, user)

    def start_grace_period_for_user(self, co, group, group_attributes, user, duration):
        """
        The grace period for user user has started. However, for the CUA this
        has no implications. Until the grace period has ended, nothing will change
        for the CUA.
        """
        self.notify.start_grace_period_for_user(co, group, group_attributes, user, duration)

    def remove_user_from_group(self, co: str, group: str, group_attributes: list, user: str) -> None:
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a user from a group. Call the auxiliary event class.
        """
        self.print(f"# Remove {user} from group {group}")
        self.update_user_in_group(group, group_attributes, user, add=False)

        self.notify.remove_user_from_group(co, group, group_attributes, user)

    def remove_graced_user_from_group(self, co: str, group: str, group_attributes: list, user: str):
        """
        Write the appropriate sara_usertools command to the bash script for
        removing a user from a graced group. Call the auxiliary event class.
        """
        self.print(f"# Grace time has ended for user {user} from group {group}")
        self.remove_user_from_group(co, group, group_attributes, user)

        self.notify.remove_graced_user_from_group(co, group, user, group_attributes)

    def update_user_in_group(self, group: str, group_attributes: list, user: str, add: bool) -> None:
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
                self.print(f"{self.modify_user_cmd}{remove}--access {self.service_name} {group} {user}\n")

            if "project_group" in attr:
                self.print(f"{self.modify_user_cmd}{remove}--group {group} {user}\n")
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

            self.print("\n" + "#" * 32)
            self.print("# Cleaning provisional status. #")
            self.print("#" * 32)
            self.print(f'if [ -f "{provisional_status_filename}" ]; then')
            self.print(f'  mv "{provisional_status_filename}" "{status_filename}"')
            self.print("else")
            self.print(
                f"  echo 'Cannot find {provisional_status_filename}. Has this script been run before?'"
            )
            self.print("fi")

        self.print("\n" + "#" * 43)
        self.print("#" + " " * 41 + "#")
        self.print("#  Script generation ended successfully.  #")
        self.print("#" + " " * 41 + "#")
        self.print("#" * 43)

        self.notify.finalize()
