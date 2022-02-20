"""Write a simple log message for each received event."""

from .sramlogger import logger
from .event_handler import EventHandler


class DummyEventHandler(EventHandler):
    """Write a simple log message for each received event."""

    def __init__(self, service, cfg, cfg_path):
        super().__init__(service, cfg, cfg_path)
        logger.info(f"service: {service}")
        logger.info(f"config: {cfg}")
        logger.info(f"config path: {cfg_path}")

    def start_of_service_processing(self, co):
        """Log the start_of_service_processing event."""
        logger.info(f"  start_of_service_processing({co})")

    def add_new_user(self, group, givenname, sn, user, mail):
        """Log the add_new_user event."""
        logger.info(f"  add_new_user({group}, {givenname}, {sn}, {user}, {mail}")

    def add_public_ssh_key(self, user, key):
        """Log the add_public_ssh_key event."""
        logger.info(f"    add_public_ssh_key({user}, {key})")

    def delete_public_ssh_key(self, user, key):
        """Log the delete_public_ssh_key event."""
        logger.info(f"    delete_public_ssh_key({self}, {user}, {key})")

    def add_new_group(self, group, attributes):
        """Log the add_new_group event."""
        logger.info(f"  add_new_group({group}, {attributes})")

    def remove_group(self, group, attributes):
        """Log the remove_group event."""
        logger.info(f"  remove_group({group}, {attributes})")

    def add_user_to_group(self, group, user, attributes: list):
        """Log the add_user_to_group event."""
        logger.info(f"  add_user_to_group({group}, {user}, {attributes})")

    def remove_user_from_group(self, group, user, attributes: list):
        """Log the remove_user_from_group event."""
        logger.info(f"  remove_user_from_group({group}, {user}, {attributes})")

    def remove_graced_user_from_group(self, group, user, attributes):
        """Log the remove_graced_user_from_group event."""
        logger.info(f"  remove_graced_user_from_group({group}, {user}, {attributes})")

    def finalize(self):
        """Log the finalize event."""
        logger.info("finalize()")
