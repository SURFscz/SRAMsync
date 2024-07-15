"""Write a simple log message for each received event."""

from datetime import timedelta
from pathlib import Path
import sys
from typing import Callable, Union

import click

from SRAMsync.common import get_attribute_from_entry
from SRAMsync.event_handler import EventHandler
from SRAMsync.sramlogger import logger
from SRAMsync.state import State
from SRAMsync.typing import EventHandlerConfig


class DummyEventHandler(EventHandler):
    """Write a simple log message for each received event."""

    def __init__(self, service: str, cfg: EventHandlerConfig, state: State, cfg_path: Path) -> None:
        super().__init__(service, cfg, state, cfg_path)
        logger.debug(
            click.style(text="service: ", fg="magenta")
            + click.style(text=service, fg=(255, 255, 255), bold=True)
        )
        logger.debug(click.style(text="config: ", fg="magenta") + str(cfg))
        logger.debug(click.style(text="config path: ", fg="magenta") + str(cfg_path))

    def process_co_attributes(self, attributes: dict[str, list[bytes]], org: str, co: str) -> None:
        logger.debug("Got attributes for %s/%s:", org, co)
        for attribute, attribute_value in attributes.items():
            logger.debug(
                click.style(text=attribute, fg="yellow")
                + " -> "
                + click.style(text=attribute_value, fg="red", bold=True)
            )

    def start_of_co_processing(self, co: str) -> None:
        """Log the start_of_co_processing event."""
        logger.info(click.style(text=f"  start_of_co_processing({co})", fg="yellow", bold=True))

    def add_new_user(
        self,
        entry: dict[str, list[bytes]],
        **kwargs: str,
    ):
        """Log the add_new_user event."""
        org: str = kwargs["org"]
        co: str = kwargs["co"]
        groups: str = kwargs["groups"]
        user: "str" = kwargs["user"]
        givenname: str = get_attribute_from_entry(entry, attribute="givenName")
        sn: str = get_attribute_from_entry(entry, attribute="sn")
        mail: str = get_attribute_from_entry(entry, attribute="mail")
        logger.info(
            "  add_new_user(%s/%s, %s, %s, %s, %s, %s",
            click.style(text=org, fg="red"),
            click.style(text=co, fg="yellow"),
            click.style(text=groups, fg="green"),
            givenname,
            sn,
            click.style(text=user, fg="cyan"),
            mail,
        )

    def get_supported_arguments(
        self,
    ) -> dict[str, dict[str, Union[Union[Callable[[str], None], Callable[[], None]], str]]]:
        return {}

    def add_public_ssh_key(self, co: str, user: str, key: str):
        """Log the add_public_ssh_key event."""
        logger.info(
            "    add_public_ssh_key(%s, %s, %s)",
            click.style(text=co, fg="yellow"),
            click.style(text=user, fg="cyan"),
            click.style(text=key, fg="white", dim=True),
        )

    def delete_public_ssh_key(self, co: str, user: str, key: str):
        """Log the delete_public_ssh_key event."""
        logger.info("    delete_public_ssh_key(%s, %s, %s)", co, user, key)

    def add_new_groups(self, co: str, groups: list[str], group_attributes: list[str]):
        """Log the add_new_group event."""
        logger.info(
            "  add_new_group(%s, %s, %s)",
            click.style(text=co, fg="yellow"),
            click.style(text=groups, fg="cyan"),
            group_attributes,
        )

    def remove_group(self, co: str, group: str, group_attributes: list[str]):
        """Log the remove_group event."""
        logger.info(
            "  remove_group(%s, %s, %s)",
            click.style(text=co, fg="yellow"),
            click.style(text=group, fg="cyan"),
            group_attributes,
        )

    def add_user_to_group(self, **kwargs: str):
        """Log the add_user_to_group event."""
        try:
            org: str = kwargs["org"]
            co: str = kwargs["co"]
            groups: str = kwargs["groups"]
            group_attributes: str = kwargs["group_attributes"]
            user: str = kwargs["user"]

            logger.info(
                "  add_user_to_group(%s/%s, %s, %s, %s)",
                click.style(text=org, fg="red"),
                click.style(text=co, fg="yellow"),
                click.style(text=groups, fg="green"),
                group_attributes,
                click.style(text=user, fg="cyan"),
            )
        except KeyError as e:
            logger.error("Missing argument for DummyEventHandler:add_user_to_group %s", e)
            sys.exit(1)

    def start_grace_period_for_user(
        self, co: str, group: str, group_attributes: list[str], user: str, duration: timedelta
    ) -> None:
        """Log the start_grace_period_for_user event."""
        logger.info(
            "  start_grace_period_for_user(%s, %s, %s, %s %s)",
            click.style(text=co, fg="yellow"),
            click.style(text=group, fg="green"),
            group_attributes,
            click.style(text=user, fg="cyan"),
            duration,
        )

    def remove_user_from_group(self, co: str, group: str, group_attributes: list[str], user: str):
        """Log the remove_user_from_group event."""
        logger.info(
            "  remove_user_from_group(%s, %s, %s, %s)",
            click.style(text=co, fg="yellow"),
            click.style(text=group, fg="green"),
            group_attributes,
            click.style(text=user, fg="cyan"),
        )

    def remove_graced_user_from_group(self, co: str, group: str, group_attributes: list[str], user: str):
        """Log the remove_graced_user_from_group event."""
        logger.info(
            "  remove_graced_user_from_group(%s, %s, %s, %s)",
            click.style(text=co, fg="yellow"),
            click.style(text=group, fg="green"),
            group_attributes,
            click.style(text=user, fg="cyan"),
        )

    def remove_user(self, user: str, state: State) -> None:
        logger.info("  remove_user(%s", click.style(text=user, fg="yellow"))

    def finalize(self) -> None:
        """Log the finalize event."""
        logger.info(click.style(text="finalize()", fg="white", bold=True))
