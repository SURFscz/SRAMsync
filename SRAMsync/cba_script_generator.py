"""
Additional functionality for CBA related accounting. The CbaScriptGenerator
class is derived from CuaScriptGenerator, because of its strong relation. By
doing so, the functionallity of CuaScriptGenerator can be resused here.
"""

import json
import sys
from typing import Any, Callable, Union, cast

import click
from pathlib import Path
from jsonschema import Draft202012Validator, ValidationError, validate

from SRAMsync.cua_script_generator import CuaScriptGenerator
from SRAMsync.json_file import JsonFile
from SRAMsync.sramlogger import logger
from SRAMsync.state import State
from SRAMsync.sync_with_sram import ConfigValidationError
from SRAMsync.typing import CbaNotificationConfig, EventHandlerConfig


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

    def __init__(self, service: str, cfg: EventHandlerConfig, state: JsonFile, path: Path) -> None:
        try:
            validate(
                schema=CbaScriptGenerator._schema,
                instance=cfg["event_handler_config"],
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )

            cua_config: EventHandlerConfig = {
                "event_handler_config": cast(CbaNotificationConfig, cfg["event_handler_config"])[
                    "cua_config"
                ],
                "secrets": cfg["secrets"],
            }
            super().__init__(service, cfg=cua_config, state=state, cfg_path=path)

            self.cfg = cast(CbaNotificationConfig, cfg["event_handler_config"])
            self._cba_co_budget_mapping_filename = ""
        except ConfigValidationError as e:
            raise e
        except ValidationError as e:
            raise ConfigValidationError(e, path) from e

    def _insert_cba_command(self, cmd: str, co: str, user: str, co_uuid: str = "") -> None:
        """Insert the cba command with arguments into the generated bash script."""
        # account = render_templated_string(self.cfg["cba_budget_account"], co=co, uid=user)
        self._print(string=f"{cmd} {self.cfg['cba_machine']} {user} {co_uuid}\n")

    def get_supported_arguments(self) -> dict[str, Any]:
        """
        Process the arguments that are passed on the command line for plugins.
        Note that not all supplied arguments are necessary supplied for a specific
        module. All plugins are passed the same list of arguments and thus a module
        can encounter an argument that is not for this module and thus must be ignored.
        An unknown argument does not mean that it is an error.
        """
        options: dict[str, dict[str, Union[Union[Callable[[str], None], Callable[[], None]], str]]] = (
            super().get_supported_arguments()
        )

        options.update(
            {
                "cba-co-budget-mapping-filename": {
                    "action": self.handle_cba_co_budget_mapping_filename,
                    "type": "path",
                    "deprecated": "cba-co-budget-mapping-filename is depricated in v4.3.0 and will be removed in v4.4.0",
                },
            }
        )

        return options

    def handle_cba_co_budget_mapping_filename(self, value: str) -> None:
        """Assign a value to self._cba_co_budget_mapping_filename"""
        self._cba_co_budget_mapping_filename = value

    def process_co_attributes(self, attributes: dict[str, list[bytes]], org: str, co: str) -> None:
        """Process the CO attributes."""
        super().process_co_attributes(attributes, org, co)

        co_uuid: str = attributes["uniqueIdentifier"][0].decode("utf-8")  # type: ignore
        key: str = f"{org}-{co}"
        if key not in self.org_co_uuids:
            self.org_co_uuids[key] = co_uuid

        try:
            with open(file=self._cba_co_budget_mapping_filename, mode="r") as fd:
                mappings = json.load(fp=fd)

            mapping_updated = False
            new_mapping = {}
            for uuid, dict_values in mappings.items():
                if uuid != co_uuid and mappings[uuid]["org"] == org and mappings[uuid]["co"] == co:
                    new_mapping[co_uuid] = dict_values
                    if "note" in new_mapping[co_uuid]:
                        logger.debug("Removing Note from %s", click.style(co_uuid, fg="blue"))
                        del new_mapping[co_uuid]["note"]
                    mapping_updated = True
                else:
                    logger.debug("No updates for %s", click.style(text=uuid, fg="blue"))
                    new_mapping[uuid] = dict_values

            if mapping_updated:
                with open(file=self._cba_co_budget_mapping_filename, mode="w") as fd:
                    json.dump(obj=new_mapping, fp=fd)
        except FileNotFoundError:
            if self._cba_co_budget_mapping_filename != "":
                logger.warn(
                    "CuaScriptGenerator: CBA CO budget mapping per file has been requested, however file '%s' does not exists.",
                    self._cba_co_budget_mapping_filename,
                )

        return super().process_co_attributes(attributes, org, co)

    def add_new_user(
        self,
        entry: dict[str, list[bytes]],
        **kwargs: str,
    ) -> None:
        """add_new_user event."""
        super().add_new_user(entry, **kwargs)

        try:
            co: str = kwargs["co"]
            user: str = kwargs["user"]
            co_uuid: str = self.org_co_uuids[f"{kwargs['org']}-{kwargs['co']}"]

            self._print(string="# Adding user CBA account.")
            self._insert_cba_command(self.cfg["cba_add_cmd"], co, user, co_uuid)
        except KeyError as e:
            logger.error("Missing(cba_script_generator) argument: %s", e)
            sys.exit(1)

    def remove_user_from_group(self, co: str, group: str, group_attributes: list[str], user: str) -> None:
        """remove_user_from_group event."""
        self._insert_cba_command(cmd=self.cfg["cba_del_cmd"], co=co, user=user)

    def remove_graced_user_from_group(
        self, co: str, group: str, group_attributes: list[str], user: str
    ) -> None:
        """remove_graced_user_from_group event."""
        super().remove_graced_user_from_group(co, group, group_attributes, user)
        self._insert_cba_command(cmd=self.cfg["cba_del_cmd"], co=co, user=user)

    def remove_user(self, user: str, state: State) -> None:
        group: str = ""

        for tmp in state.get_known_groups():
            if state.is_user_member_of_group(dest_group_names=[tmp], user=user):
                group = tmp
                break

        co: str = state["users"][user]["CO"]
        org: str = state["groups"][group]["sram"]["org"]
        co_uuid: str = self.org_co_uuids[f"{org}-{co}"]

        logger.debug(f"CbaScriptGenerator: removing user: {user} for CO: {co}")

        self._insert_cba_command(cmd=self.cfg["cba_del_cmd"], co_uuid=co_uuid, user=user)
        super().remove_user(user, state)
