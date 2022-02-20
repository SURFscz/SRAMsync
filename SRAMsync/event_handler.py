"""
The event_handler class must be used as a base class for implementing
what needs to be done when the sync-with-sram main loopt emits events.
"""

from abc import ABC, abstractmethod


class EventHandler(ABC):
    """Abstract implementatation of the EventHandler class."""

    def __init__(self, service, cfg, cfg_path):
        pass

    @abstractmethod
    def start_of_service_processing(self, co):
        """start_of_service_processing event."""

    @abstractmethod
    def add_new_user(self, group, givenname, sn, user, mail):
        """add_new_user event."""

    @abstractmethod
    def add_public_ssh_key(self, user, key):
        """add_public_ssh_key event."""

    @abstractmethod
    def delete_public_ssh_key(self, user, key):
        """delete_public_ssh_key event."""

    @abstractmethod
    def add_new_group(self, group, attributes):
        """add_new_group event."""

    @abstractmethod
    def remove_group(self, group, attributes):
        """remove_group event."""

    @abstractmethod
    def add_user_to_group(self, group, user, attributes):
        """add_user_to_group event."""

    @abstractmethod
    def remove_user_from_group(self, group, user, attributes: list):
        """remove_user_from_group event."""

    @abstractmethod
    def remove_graced_user_from_group(self, group, user, attributes):
        """remove_graced_user_from_group event."""

    @abstractmethod
    def finalize(self):
        """finalize event."""
