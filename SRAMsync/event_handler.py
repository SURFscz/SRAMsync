"""
The event_handler class must be used as a base class for implementing
what needs to be done when the sync-with-sram main loop emits events.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple

from SRAMsync.state import State


class EventHandler(ABC):
    """Abstract implementation of the EventHandler class."""

    @abstractmethod
    def __init__(self, service: str, cfg: Dict, state: State, cfg_path: List[str], args: Tuple[str]):
        pass

    @abstractmethod
    def process_co_attributes(self, attributes: Dict[str, str], org: str, co: str) -> None:
        """Provide the UUID for the current org and co."""

    @abstractmethod
    def start_of_co_processing(self, co: str):
        """start_of_co_processing event."""

    @abstractmethod
    def add_new_user(
        self,
        co: str,
        groups: List[str],
        user: str,
        group_attributes: List[str],
        entry: Dict[str, List[bytes]],
    ):
        """add_new_user event."""

    @abstractmethod
    def add_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """add_public_ssh_key event."""

    @abstractmethod
    def delete_public_ssh_key(self, co: str, user: str, key: str):
        """delete_public_ssh_key event."""

    @abstractmethod
    def add_new_groups(self, co: str, groups: List[str], group_attributes: List[str]):
        """add_new_group event."""

    @abstractmethod
    def remove_group(self, co: str, group: str, group_attributes: List[str]):
        """remove_group event."""

    @abstractmethod
    def add_user_to_group(self, co, group, group_attributes, user):
        """add_user_to_group event."""

    @abstractmethod
    def start_grace_period_for_user(self, co, group, group_attributes, user, duration):
        """start_grace_period_for_user event."""

    @abstractmethod
    def remove_user_from_group(self, co, group, group_attributes: list, user):
        """remove_user_from_group event."""

    @abstractmethod
    def remove_graced_user_from_group(self, co, group, group_attributes, user):
        """remove_graced_user_from_group event."""

    @abstractmethod
    def finalize(self):
        """finalize event."""
