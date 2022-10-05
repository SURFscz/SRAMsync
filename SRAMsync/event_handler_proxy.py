"""
Proxy class for EventHandler. Multiple EventHanlders can be configured
in parallel. This class is given all those instances at instantiation.
Calling one of the events loops over all known instances and calls the
same function of each instance.
"""

from typing import List
from SRAMsync.event_handler import EventHandler


class EventHandlerProxy(EventHandler):
    """Proxy class to iterate over EventHandlers."""

    def __init__(self, event_handlers):
        super().__init__(None, None, None, None, None)
        self.event_handlers = event_handlers

    def start_of_co_processing(self, co):
        """Call start_of_co_processing event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.start_of_co_processing(co)

    def add_new_user(self, co: str, groups: List[str], user: str, entry: dict):
        """Call add_new_user event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.add_new_user(co, groups, user, entry)

    def add_public_ssh_key(self, co, user, key):
        """Call add_public_ssh_key event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.add_public_ssh_key(co, user, key)

    def delete_public_ssh_key(self, co, user, key):
        """Call delete_public_ssh_key event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.delete_public_ssh_key(co, user, key)

    def add_new_group(self, co, group, group_attributes):
        """Call add_new_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.add_new_group(co, group, group_attributes)

    def remove_group(self, co, group, group_attributes):
        """Call remove_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.remove_group(co, group, group_attributes)

    def add_user_to_group(self, co, group, group_attributes, user):
        """Call add_user_to_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.add_user_to_group(co, group, group_attributes, user)

    def start_grace_period_for_user(self, co, group, group_attributes, user, duration):
        """Call start_grace_period_for_user event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.start_grace_period_for_user(co, group, group_attributes, user, duration)

    def remove_user_from_group(self, co, group, group_attributes: list, user):
        """Call remove_user_from_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.remove_user_from_group(co, group, group_attributes, user)

    def remove_graced_user_from_group(self, co, group, group_attributes, user):
        """Call remove_graced_user_from_group event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.remove_graced_user_from_group(co, group, group_attributes, user)

    def finalize(self):
        """Call finalize event for all EventHandlers."""
        for event_handler in self.event_handlers:
            event_handler.finalize()
