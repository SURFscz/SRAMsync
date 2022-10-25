"""
Abstract class definition for keeping track of the last known and current state
of the SRAMsync process.
"""

from datetime import datetime
from typing import Any, List

from abc import ABC, abstractmethod


class NoGracePeriodForGroupError(Exception):
    """
    Exception in case no grace period was found in the attributes list for
    group definition in the configuration file.
    """


class UnkownGroup(Exception):
    """Exception in case an unknown group is acccessed."""

    def __init__(self, unknown_group):
        super().__init__()
        self._unknown_group = unknown_group


class State(ABC):
    """
    Class for keeping track of the last known and current state of the SRAMsync
    process. Either state can be querried for known or unknown things.
    """

    def __init__(self, cfg: dict):
        """init"""
        self.cfg = cfg

    def get_config(self) -> dict:
        """Get the config for the State class."""
        return self.cfg

    def get_state_name(self) -> str:
        """Get the name from the config for this State."""
        return self.cfg["name"]

    @abstractmethod
    def __getitem__(self, key: str) -> Any:
        """Return item."""

    @abstractmethod
    def __setitem__(self, key: str, value: Any) -> None:
        """Set value"""

    @abstractmethod
    def dump_state(self) -> None:
        """Dump the current state."""

    @abstractmethod
    def get_last_known_state(self) -> dict:
        """Return the last known state."""

    @abstractmethod
    def is_known_user(self, user: str) -> bool:
        """Check if the user is known from the last state."""

    @abstractmethod
    def is_known_group(self, groups: List[str]) -> bool:
        """Check if the group is known from the last state."""

    @abstractmethod
    def is_user_member_of_group(self, dest_group_names: List[str], user: str) -> bool:
        """Check is the user is member of the destination group."""

    @abstractmethod
    def is_found_group(self, group: str) -> bool:
        """Check if the group is in the encounterd groups."""

    @abstractmethod
    def add_user(self, user: str, co: str) -> None:
        """Add user."""

    @abstractmethod
    def add_groups(
        self, dest_group_names: List[str], co: str, sram_group: str, group_attributes: list
    ) -> None:
        """Add a new group."""

    @abstractmethod
    def add_group_member(self, dest_group_names: List[str], user: str) -> None:
        """Add member to a group."""

    @abstractmethod
    def get_all_known_users_from_group(self, group) -> List[str]:
        """Get all users from the known group."""

    @abstractmethod
    def get_added_group(self, group: str) -> dict:
        """Get added group."""

    @abstractmethod
    def get_added_groups(self) -> list:
        """Get added groups."""

    @abstractmethod
    def get_co_of_known_group(self, group) -> str:
        """Get the CO name of the known group."""

    @abstractmethod
    def get_known_group(self, group: str) -> dict:
        """Get known group."""

    @abstractmethod
    def get_known_groups(self) -> list:
        """Get known groups."""

    @abstractmethod
    def get_known_group_attributes(self, group: str) -> list:
        """Get attributes for known group."""

    @abstractmethod
    def get_known_groups_and_attributes(self) -> dict:
        """Get all known groups and their attributes."""

    @abstractmethod
    def get_removed_users(self, group: str) -> list:
        """Get the users that have been removed since the last synchronisation for the group."""

    @abstractmethod
    def get_known_user_public_ssh_keys(self, user: str) -> set:
        """Get the set of known public ssh keys for the user."""

    @abstractmethod
    def set_user_public_ssh_keys(self, user: str, ssh_public_keys: set) -> None:
        """Set the public ssh keys for the user."""

    @abstractmethod
    def set_graced_period_for_user(self, group: str, user: str, grace_period: datetime) -> None:
        """Set the grace period for the user in group group."""

    @abstractmethod
    def invalidate_all_group_members(self, group: str):
        """If necessay, invalidate all group members."""
