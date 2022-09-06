"""
Concreet implementation of the State abstract base class. It implements
the State class based on a JSON file.
"""

import json
from datetime import datetime
from typing import Any

from jsonschema import validate

from SRAMsync.common import render_templated_string
from SRAMsync.state import State, UnkownGroup


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
        },
        "required": ["status_filename"],
        "additionalProperties": False,
    }

    def __init__(self, cfg: dict, **kwargs: str):
        super().__init__(cfg, **kwargs)

        validate(schema=self._schema, instance=cfg)

        self.status_filename = render_templated_string(cfg["status_filename"], **kwargs)
        try:
            with open(self.status_filename, encoding="utf8") as fd:
                self._last_known_state = json.load(fd)
        except FileNotFoundError:
            self._last_known_state = {"users": {}, "groups": {}}

        self._new_state = {"users": {}, "groups": {}}

    def __getitem__(self, key: str) -> Any:
        return self._last_known_state[key]

    def __setitem__(self, key: str, value: Any) -> None:
        print(key, value)
        if key not in self._new_state:
            self._new_state[key] = value
        self._new_state[key] = value

    def dump_state(self) -> None:
        try:
            with open(self.status_filename, "w", encoding="utf8") as fd:
                json.dump(self._new_state, fd, indent=2, sort_keys=True)
                fd.write("\n")
        except FileNotFoundError:
            pass

    def is_known_user(self, user: str) -> bool:
        return user in self._last_known_state["users"]

    def is_known_group(self, group) -> bool:
        return group in self._last_known_state["groups"]

    def is_user_member_of_group(self, dest_group_name, user) -> bool:
        try:
            return user in self._last_known_state["groups"][dest_group_name]["members"]
        except KeyError:
            raise UnkownGroup(dest_group_name)

    def is_found_group(self, group: str) -> bool:
        return group in self._new_state["groups"]

    def add_user(self, user: str, co: str) -> None:
        self._new_state["users"][user] = {"CO": co}

    def add_group(self, dest_group_name: str, co: str, sram_group: str, group_attributes: list) -> None:
        if dest_group_name not in self._new_state["groups"]:
            self._new_state["groups"][dest_group_name] = {
                "members": [],
                "attributes": group_attributes,
                "sram": {
                    "CO": co,
                    "sram-group": sram_group,
                },
            }

    def add_member(self, dest_group_name: str, user: str) -> None:
        if (
            dest_group_name in self._new_state["groups"]
            and "members" in self._new_state["groups"][dest_group_name]
        ):
            self._new_state["groups"][dest_group_name]["members"].append(user)

    def get_added_group(self, group: str) -> dict:
        return self._new_state["groups"][group]

    def get_added_groups(self) -> list:
        return list(self._new_state["groups"].keys())

    def get_co_of_known_group(self, group) -> str:
        return self._last_known_state["groups"][group]["sram"]["CO"]

    def get_known_group(self, group: str) -> dict:
        return self._last_known_state["groups"][group]

    def get_known_groups(self) -> list:
        return list(self._last_known_state["groups"].keys())

    def get_known_group_attributes(self, group: str) -> list:
        return self._last_known_state["groups"][group]["attributes"]

    def get_known_groups_and_attributes(self) -> dict:
        return self._last_known_state["groups"]

    def get_removed_users(self, group: str) -> list:
        removed_users = [
            user
            for user in self._last_known_state["groups"][group]["members"]
            if user not in self._new_state["groups"][group]["members"]
        ]
        return removed_users

    def get_known_user_public_ssh_keys(self, user: str) -> set:
        try:
            return set(self._last_known_state["users"][user]["sshPublicKey"])
        except KeyError:
            return set()

    def set_user_public_ssh_keys(self, user: str, ssh_public_keys: set) -> None:
        if ssh_public_keys:
            try:
                self._new_state["users"][user]["sshPublicKey"] = list(ssh_public_keys)
            except TypeError:
                pass

    def set_graced_period_for_user(self, group: str, user: str, grace_period: datetime) -> None:
        if "graced_users" not in self._new_state["groups"][group]:
            self._new_state["groups"][group]["graced_users"] = {}
        if user not in self._new_state["groups"][group]["graced_users"]:
            self._new_state["groups"][group]["graced_users"] = {
                user: datetime.strftime(grace_period, "%Y-%m-%d %H:%M:%S%z")
            }
