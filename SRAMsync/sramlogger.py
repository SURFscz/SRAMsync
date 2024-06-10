"""
Singleton logging with click.
"""

import logging

import click_logging
from typing import cast

#  Adjust some of the colour style of click_logging.
click_logging_styles = {"debug": dict(fg="green")}

logger = cast(
    logging.Logger,
    click_logging.basic_config(logging.getLogger("SRAMsync"), style_kwargs=click_logging_styles),  # type: ignore
)
