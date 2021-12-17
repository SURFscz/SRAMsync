import logging
import click_logging

#  Adjust some of the colour style of click_logging.
click_logging_styles = {"debug": dict(fg="green")}

logger = click_logging.basic_config(logging.getLogger(__name__), style_kwargs=click_logging_styles)
