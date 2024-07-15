"""
Concreet implementation of the State abstract base class. It implements
the State class based on a JSON file.
"""

import json
from datetime import datetime
from typing import Any, Literal, Optional, Union, cast

from jsonschema import validate

from SRAMsync.common import render_templated_string
from SRAMsync.state import State, UnkownGroup
from SRAMsync.typing import StateGroup, StateUser, StatusFilenames, StateFile


class JsonFile(State):
    """
    Provide state infomation about the last known and current state. The
    latest state infomation is kept in a JSON file.
    """

    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "status_filename": {"type": "string"},
            "provisional_status_filename": {"type": "string"},
        },
        "required": ["status_filename"],
        "additionalProperties": False,
    }

    def __init__(self, cfg: StatusFilenames, **kwargs: str) -> None:
        super().__init__(cfg)

        validate(schema=self._schema, instance=cfg)

        if "provisional_status_filename" in cfg:
            self.provisional_status_filename = render_templated_string(
                template_string=cfg["provisional_status_filename"], **kwargs
            )

        self.status_filename = render_templated_string(template_string=cfg["status_filename"], **kwargs)

        try:
            with open(file=self.status_filename, encoding="utf8") as fd:
                self._last_known_state: StateFile = json.load(fp=fd)
        except FileNotFoundError:
            self._last_known_state = cast(StateFile, {"users": {}, "groups": {}})

        self.cfg = cfg
        self._new_state: StateFile = {"users": {}, "groups": {}}

    def __getitem__(
        self, key: Literal["users", "groups"]
    ) -> Union[dict[str, StateGroup], dict[str, StateUser]]:
        return self._last_known_state[key]

    def __setitem__(self, key: str, value: Any) -> None:
        print(key, value)
        if key not in self._new_state:
            self._new_state[key] = value
        self._new_state[key] = value

    def get_status_filename(self) -> str:
        """Return the status file name."""
        return self.cfg["status_filename"]

    def get_provisional_status_filename(self) -> Optional[str]:
        """If the provisional_status_filename is defined, return it."""
        if "provisional_status_filename" in self.cfg:
            return self.provisional_status_filename

        return None

    def dump_state(self) -> None:
        try:
            if "provisional_status_filename" in self.cfg:
                status_filename: str = self.provisional_status_filename
            else:
                status_filename = self.status_filename

            with open(file=status_filename, mode="w", encoding="utf8") as fd:
                json.dump(obj=self._new_state, fp=fd, indent=2, sort_keys=True)
                fd.write("\n")
        except FileNotFoundError:
            pass

    def get_last_known_state(self) -> StateFile:
        return self._last_known_state

    def is_known_user(self, user: str) -> bool:
        return user in self._last_known_state["users"]

    def is_known_group(self, groups: list[str]) -> bool:
        known = True

        for group in groups:
            known &= group in self._last_known_state["groups"]

        return known

    def is_user_member_of_group(self, dest_group_names: list[str], user: str) -> bool:
        if not dest_group_names:
            return False

        for dest_group_name in dest_group_names:
            try:
                if dest_group_name not in self._last_known_state["groups"]:
                    return False

                if user not in self._last_known_state["groups"][dest_group_name]["members"]:
                    return False
            except KeyError as e:
                raise UnkownGroup(unknown_group=dest_group_name) from e

        return True

    def is_found_group(self, group: str) -> bool:
        return group in self._new_state["groups"]

    def add_user(self, user: str, co: str) -> None:
        self._new_state["users"][user] = cast(StateUser, {"CO": co})

    def add_groups(
        self, dest_group_names: list[str], co: str, sram_group: str, group_attributes: list[str]
    ) -> None:
        for dest_group_name in dest_group_names:
            if dest_group_name not in self._new_state["groups"]:
                self._new_state["groups"][dest_group_name] = {
                    "members": [],
                    "attributes": group_attributes,
                    "sram": {"CO": co, "sram-group": sram_group, "org": ""},
                    "graced_users": {},
                }

    def add_group_member(self, dest_group_names: list[str], user: str) -> None:
        for dest_group_name in dest_group_names:
            if (
                dest_group_name in self._new_state["groups"]
                and "members" in self._new_state["groups"][dest_group_name]
            ):
                self._new_state["groups"][dest_group_name]["members"].append(user)

    def get_all_known_users_from_group(self, group: str) -> list[str]:
        return self._last_known_state["groups"][group]["members"]

    def get_added_group(self, group: str) -> StateGroup:
        return self._new_state["groups"][group]

    def get_added_groups(self) -> list[str]:
        return list(self._new_state["groups"].keys())

    def get_org_of_known_group(self, group: str) -> str:
        return self._last_known_state["groups"][group]["sram"]["org"]

    def get_co_of_known_group(self, group: str) -> str:
        return self._last_known_state["groups"][group]["sram"]["CO"]

    def get_known_group(self, group: str) -> StateGroup:
        return self._last_known_state["groups"][group]

    def get_known_groups(self) -> list[str]:
        return list(self._last_known_state["groups"].keys())

    def get_known_group_attributes(self, group: str) -> list[str]:
        return self._last_known_state["groups"][group]["attributes"]

    def get_known_groups_and_attributes(self) -> dict[str, StateGroup]:
        return self._last_known_state["groups"]

    def get_removed_users(self, group: str) -> list[str]:
        if group not in self._new_state["groups"]:
            return self._last_known_state["groups"][group]["members"]

        removed_users: list[str] = [
            user
            for user in self._last_known_state["groups"][group]["members"]
            if user not in self._new_state["groups"][group]["members"]
        ]
        return removed_users

    def get_removed_users_f(self) -> set[str]:
        users_in_sram: list[str] = [user for user in self._new_state["users"]]
        last_known_users: list[str] = [user for user in self._last_known_state["users"]]

        return set(last_known_users) - set(users_in_sram)

    def get_known_user_public_ssh_keys(self, user: str) -> set[str]:
        try:
            return set(self._last_known_state["users"][user]["sshPublicKey"])
        except KeyError:
            return set()

    def set_user_public_ssh_keys(self, user: str, ssh_public_keys: set[str]) -> None:
        if ssh_public_keys:
            try:
                self._new_state["users"][user]["sshPublicKey"] = list(ssh_public_keys)
            except TypeError:
                pass

    def set_graced_period_for_user(self, group: str, user: str, grace_period: datetime) -> None:
        if group not in self._new_state["groups"]:
            self._new_state["groups"][group] = self._last_known_state["groups"][group]

        if user in self._new_state["groups"][group]["members"]:
            self._new_state["groups"][group]["members"].remove(user)

        if "graced_users" not in self._new_state["groups"][group]:
            self._new_state["groups"][group]["graced_users"] = {}

        if user not in self._new_state["groups"][group]["graced_users"]:
            self._new_state["groups"][group]["graced_users"][user] = datetime.strftime(
                grace_period, "%Y-%m-%d %H:%M:%S%z"
            )

    def invalidate_all_group_members(self, group: str) -> None:
        self._last_known_state["groups"][group]["members"] = []
