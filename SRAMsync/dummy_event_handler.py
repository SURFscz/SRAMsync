"""Write a simple log message for each received event."""

from .sramlogger import logger
from .event_handler import EventHandler


class DummyEventHandler(EventHandler):
    """Write a simple log message for each received event."""

    def __init__(self, service, cfg, cfg_path, **args):
        super().__init__(service, cfg, cfg_path, **args)
        logger.info(f"service: {service}")
        logger.info(f"config: {cfg}")
        logger.info(f"config path: {cfg_path}")

    def start_of_co_processing(self, co):
        """Log the start_of_co_processing event."""
        logger.info(f"  start_of_co_processing({co})")

    def add_new_user(self, co, group, givenname, sn, user, mail):
        """Log the add_new_user event."""
        logger.info(f"  add_new_user({co}, {group}, {givenname}, {sn}, {user}, {mail}")

    def add_public_ssh_key(self, co, user, key):
        """Log the add_public_ssh_key event."""
        logger.info(f"    add_public_ssh_key({co}, {user}, {key})")

    def delete_public_ssh_key(self, co, user, key):
        """Log the delete_public_ssh_key event."""
        logger.info(f"    delete_public_ssh_key({co}, {user}, {key})")

    def add_new_group(self, co, group, group_attributes):
        """Log the add_new_group event."""
        logger.info(f"  add_new_group({co}, {group}, {group_attributes})")

    def remove_group(self, co, group, group_attributes):
        """Log the remove_group event."""
        logger.info(f"  remove_group({co}, {group}, {group_attributes})")

    def add_user_to_group(self, co, group, group_attributes: list, user):
        """Log the add_user_to_group event."""
        logger.info(f"  add_user_to_group({co}, {group}, {group_attributes}, {user})")

    def start_grace_period_for_user(self, co, group: str, group_attributes: list, user: str, duration: str):
        """Log the start_grace_period_for_user event."""
        logger.info(f"  start_grace_period_for_user({co}, {group}, {group_attributes}, {user} {duration})")

    def remove_user_from_group(self, co, group, group_attributes: list, user):
        """Log the remove_user_from_group event."""
        logger.info(f"  remove_user_from_group({co}, {group}, {group_attributes}, {user})")

    def remove_graced_user_from_group(self, co, group, group_attributes, user):
        """Log the remove_graced_user_from_group event."""
        logger.info(f"  remove_graced_user_from_group({co}, {group}, {group_attributes}, {user})")

    def finalize(self):
        """Log the finalize event."""
        logger.info("finalize()")
