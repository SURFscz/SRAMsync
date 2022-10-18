"""
Additional functionality for CBA related accounting. The CbaScriptGenerator
class is derived from CuaScriptGenerator, because of its strong relation. By
doing so, the functionallity of CuaScriptGenerator can be resused here.
"""

from typing import Dict, List
from jsonschema import ValidationError, validate

from SRAMsync.cua_script_generator import CuaScriptGenerator
from SRAMsync.sync_with_sram import ConfigValidationError
from SRAMsync.state import State


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

    def __init__(self, service: str, cfg: dict, state: State, path: str, **args) -> None:
        try:
            validate(schema=CbaScriptGenerator._schema, instance=cfg["event_handler_config"])
            super().__init__(service, cfg["cua_config"], state, path, **args)
            self.cfg = cfg["event_handler_config"]
        except ConfigValidationError as e:
            raise e
        except ValidationError as e:
            raise ConfigValidationError(e, path) from e

    def _insert_cba_command(self, cmd: str, user: str) -> None:
        """Insert the cba command with arguments into the generated bash script."""
        self._print(
            f"{cmd} --machine {self.cfg['cba_machine']} "
            f"--account {self.cfg['cba_budget_account']} --user {user}\n"
        )

    def add_new_user(self, co: str, groups: List[str], user: str, entry: Dict[str, List[bytes]]) -> None:
        """add_new_user event."""
        super().add_new_user(co, groups, user, entry)
        self._print("# Adding user CBA account.")
        self._insert_cba_command(self.cfg["cba_add_cmd"], user)

    def remove_user_from_group(self, co: str, group: str, group_attributes: list, user: str):
        """remove_user_from_group event."""
        super().remove_user_from_group(co, group, group_attributes, user)
        self._insert_cba_command(self.cfg["cba_del_cmd"], user)

    def remove_graced_user_from_group(self, co: str, group: str, group_attributes: list, user: str) -> None:
        """remove_graced_user_from_group event."""
        super().remove_graced_user_from_group(co, group, group_attributes, user)
        self._insert_cba_command(self.cfg["cba_del_cmd"], user)
