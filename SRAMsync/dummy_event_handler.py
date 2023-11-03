"""Write a simple log message for each received event."""

from typing import Dict, List, Union

import click

from SRAMsync.common import get_attribute_from_entry
from SRAMsync.event_handler import EventHandler
from SRAMsync.sramlogger import logger


class DummyEventHandler(EventHandler):
    """Write a simple log message for each received event."""

    def __init__(self, service, cfg, state, cfg_path, args):
        super().__init__(service, cfg, state, cfg_path, args)
        logger.debug(click.style("service: ", fg="magenta") + click.style(service, fg="bright_white"))
        logger.debug(click.style("config: ", fg="magenta") + str(cfg))
        logger.debug(click.style("config path: ", fg="magenta") + str(cfg_path))

    def process_co_attributes(self, attributes: Dict[str, str], org: str, co: str) -> None:
        for attribute in attributes:
            print(f"{attribute[0]} -> {attribute[1]}")

    def start_of_co_processing(self, co):
        """Log the start_of_co_processing event."""
        logger.info(click.style(f"  start_of_co_processing({co})", fg="yellow", bold=True))

    def add_new_user(
        self, co: str, group: Union[str, List[str]], user: str, group_attributes: List[str], entry: dict
    ):
        """Log the add_new_user event."""
        givenname = get_attribute_from_entry(entry, "givenName")
        sn = get_attribute_from_entry(entry, "sn")
        mail = get_attribute_from_entry(entry, "mail")
        logger.info(
            "  add_new_user(%s, %s, %s, %s, %s, %s",
            click.style(co, fg="yellow"),
            click.style(group, fg="green"),
            givenname,
            sn,
            click.style(user, fg="cyan"),
            mail,
        )

    def add_public_ssh_key(self, co, user, key):
        """Log the add_public_ssh_key event."""
        logger.info(
            "    add_public_ssh_key(%s, %s, %s)",
            click.style(co, fg="yellow"),
            click.style(user, fg="cyan"),
            click.style(key, fg="white", dim=True),
        )

    def delete_public_ssh_key(self, co, user, key):
        """Log the delete_public_ssh_key event."""
        logger.info("    delete_public_ssh_key(%s, %s, %s)", co, user, key)

    def add_new_groups(self, co, group, group_attributes):
        """Log the add_new_group event."""
        logger.info(
            "  add_new_group(%s, %s, %s)",
            click.style(co, fg="yellow"),
            click.style(group, fg="cyan"),
            group_attributes,
        )

    def remove_group(self, co, group, group_attributes):
        """Log the remove_group event."""
        logger.info(
            "  remove_group(%s, %s, %s)",
            click.style(co, fg="yellow"),
            click.style(group, fg="cyan"),
            group_attributes,
        )

    def add_user_to_group(self, co, group, group_attributes: list, user):
        """Log the add_user_to_group event."""
        logger.info(
            "  add_user_to_group(%s, %s, %s, %s)",
            click.style(co, fg="yellow"),
            click.style(group, fg="green"),
            group_attributes,
            click.style(user, fg="cyan"),
        )

    def start_grace_period_for_user(self, co, group: str, group_attributes: list, user: str, duration: str):
        """Log the start_grace_period_for_user event."""
        logger.info(
            "  start_grace_period_for_user(%s, %s, %s, %s %s)",
            click.style(co, fg="yellow"),
            click.style(group, fg="green"),
            group_attributes,
            click.style(user, fg="cyan"),
            duration,
        )

    def remove_user_from_group(self, co, group, group_attributes: list, user):
        """Log the remove_user_from_group event."""
        logger.info(
            "  remove_user_from_group(%s, %s, %s, %s)",
            click.style(co, fg="yellow"),
            click.style(group, fg="green"),
            group_attributes,
            click.style(user, fg="cyan"),
        )

    def remove_graced_user_from_group(self, co, group, group_attributes, user):
        """Log the remove_graced_user_from_group event."""
        logger.info(
            "  remove_graced_user_from_group(%s, %s, %s, %s)",
            click.style(co, fg="yellow"),
            click.style(group, fg="green"),
            group_attributes,
            click.style(user, fg="cyan"),
        )

    def finalize(self):
        """Log the finalize event."""
        logger.info(click.style("finalize()", fg="white", bold=True))
