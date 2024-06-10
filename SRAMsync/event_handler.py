"""
The event_handler class must be used as a base class for implementing
what needs to be done when the sync-with-sram main loop emits events.
"""

from abc import ABC, abstractmethod
from typing import Any

from SRAMsync.state import State
from SRAMsync.typing import EventHandlerConfig


class EventHandler(ABC):
    """Abstract implementation of the EventHandler class."""

    @abstractmethod
    def __init__(self, service: str, cfg: EventHandlerConfig, state: State, cfg_path: list[str]):
        pass

    @abstractmethod
    def get_supported_arguments(self) -> dict[str, Any]:
        """Get the argument the evenethandler supports."""

    @abstractmethod
    def process_co_attributes(self, attributes: dict[str, str], org: str, co: str) -> None:
        """Provide the UUID for the current org and co."""

    @abstractmethod
    def start_of_co_processing(self, co: str):
        """start_of_co_processing event."""

    @abstractmethod
    def add_new_user(
        self,
        entry: dict[str, list[bytes]],
        **kwargs: Any,
    ):
        """add_new_user event."""

    @abstractmethod
    def add_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """add_public_ssh_key event."""

    @abstractmethod
    def delete_public_ssh_key(self, co: str, user: str, key: str):
        """delete_public_ssh_key event."""

    @abstractmethod
    def add_new_groups(self, co: str, groups: list[str], group_attributes: list[str]):
        """add_new_group event."""

    @abstractmethod
    def remove_group(self, co: str, group: str, group_attributes: list[str]):
        """remove_group event."""

    @abstractmethod
    def add_user_to_group(self, **kwargs: str):
        """add_user_to_group event."""

    @abstractmethod
    def start_grace_period_for_user(
        self, co: str, group: str, group_attributes: list[str], user: str, duration: str
    ):
        """start_grace_period_for_user event."""

    @abstractmethod
    def remove_user_from_group(self, co: str, group: str, group_attributes: list[str], user: str):
        """remove_user_from_group event."""

    @abstractmethod
    def remove_graced_user_from_group(self, co: str, group: str, group_attributes: list[str], user: str):
        """remove_graced_user_from_group event."""

    @abstractmethod
    def finalize(self):
        """finalize event."""
