"""
Proxy class for EventHandler. Multiple EventHanlders can be configured
in parallel. This class is given all those instances at instantiation.
Calling one of the events loops over all known instances and calls the
same function of each instance.
"""

from datetime import timedelta
from typing import Any

from SRAMsync.event_handler import EventHandler
from SRAMsync.state import State


class EventHandlerProxy(EventHandler):
    """Proxy class to iterate over EventHandlers."""

    def __init__(self, event_handlers: list[EventHandler]) -> None:
        self.event_handlers = event_handlers

    def get_supported_arguments(self) -> dict[str, Any]:
        return super().get_supported_arguments()

    def start_of_co_processing(self, co: str) -> None:
        """Call start_of_co_processing event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.start_of_co_processing(co)

    def process_co_attributes(self, attributes: dict[str, list[bytes]], org: str, co: str) -> None:
        """Call process_co_attributes event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.process_co_attributes(attributes, org, co)

    def add_new_user(
        self,
        entry: dict[str, list[bytes]],
        **kwargs: Any,
    ) -> None:
        """Call add_new_user event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.add_new_user(entry, **kwargs)

    def add_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """Call add_public_ssh_key event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.add_public_ssh_key(co, user, key)

    def delete_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """Call delete_public_ssh_key event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.delete_public_ssh_key(co, user, key)

    def add_new_groups(self, co: str, groups: list[str], group_attributes: list[str]) -> None:
        """Call add_new_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.add_new_groups(co, groups, group_attributes)

    def remove_group(self, co: str, group: str, group_attributes: list[str]) -> None:
        """Call remove_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.remove_group(co, group, group_attributes)

    def add_user_to_group(self, **kwargs: Any) -> None:
        """Call add_user_to_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.add_user_to_group(**kwargs)

    def start_grace_period_for_user(
        self, co: str, group: str, group_attributes: list[str], user: str, duration: timedelta
    ) -> None:
        """Call start_grace_period_for_user event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.start_grace_period_for_user(co, group, group_attributes, user, duration)

    def remove_user_from_group(self, co: str, group: str, group_attributes: list[str], user: str) -> None:
        """Call remove_user_from_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.remove_user_from_group(co, group, group_attributes, user)

    def remove_graced_user_from_group(
        self, co: str, group: str, group_attributes: list[str], user: str
    ) -> None:
        """Call remove_graced_user_from_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.remove_graced_user_from_group(co, group, group_attributes, user)

    def remove_user(self, user: str, state: State) -> None:
        """Call remove_user for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.remove_user(user=user, state=state)

    def finalize(self) -> None:
        """Call finalize event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.finalize()
