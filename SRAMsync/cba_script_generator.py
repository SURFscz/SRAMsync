"""
Additional functionality for CBA related accounting. The CbaScriptGenerator
class is derived from CuaScriptGenerator, because of its strong relation. By
doing so, the functionallity of CuaScriptGenerator can be resused here.
"""

from jsonschema import ValidationError, validate

from .cua_script_generator import CuaScriptGenerator
from .sync_with_sram import ConfigValidationError


class CbaScriptGenerator(CuaScriptGenerator):
    """
    Class for inserting additional commands in the bash script that the
    CuaScriptGenerator class generates. These extra command insert relevant
    account information.
    """

    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "cba_add_cmd": {"type": "string"},
            "cba_del_cmd": {"type": "string"},
            "cba_machine": {"type": "string"},
            "cba_budget_account": {"type": "string"},
            "cua_config": {"type": "object"},
        },
        "required": ["cba_add_cmd", "cba_del_cmd", "cba_machine", "cba_budget_account", "cua_config"],
    }

    def __init__(self, service: str, cfg: dict, path: str) -> None:
        try:
            validate(schema=CbaScriptGenerator._schema, instance=cfg)
            super().__init__(service, cfg["cua_config"], path)
            self.cfg = cfg
        except ConfigValidationError as e:
            raise e
        except ValidationError as e:
            raise ConfigValidationError(e, path) from e

    def add_new_user(self, group: str, givenname: str, sn: str, user: str, mail: str) -> None:
        """add_new_user event."""
        super().add_new_user(group, givenname, sn, user, mail)
        self.print("# Adding user CBA account.")
        self.insert_cba_command(self.cfg["cba_add_cmd"], user)

    def start_grace_period_for_user(self, group: str, group_attributes: list, user: str, duration: str):
        """start_grace_period_for_user event."""
        super().start_grace_period_for_user(group, group_attributes, user, duration)

    def remove_user_from_group(self, group: str, group_attributes: list, user: str):
        """remove_user_from_group event."""
        super().remove_user_from_group(group, group_attributes, user)
        self.insert_cba_command(self.cfg["cba_del_cmd"], user)

    def remove_graced_user_from_group(self, group: str, group_attributes: list, user: str) -> None:
        """remove_graced_user_from_group event."""
        super().remove_graced_user_from_group(group, group_attributes, user)
        self.insert_cba_command(self.cfg["cba_del_cmd"], user)

    def insert_cba_command(self, cmd: str, user: str) -> None:
        """Insert the cba command with arguments into the generated bash script."""
        self.print(
            f"{cmd} --machine {self.cfg['cba_machine']} "
            f"--account {self.cfg['cba_budget_account']} --user {user}\n"
        )
