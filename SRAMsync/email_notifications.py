"""
Send e-mails for each emited event from the sync-with-sram main loop. For which
events to send email is configurable and also some basic formatting can be
applied.
"""

from datetime import timedelta
import smtplib
import ssl
import sys
from email.message import EmailMessage
from email.utils import formatdate
from typing import Any, Dict, List, cast

import click
from jsonschema import Draft202012Validator, ValidationError, validate

from SRAMsync.cba_script_generator import Path
from SRAMsync.common import get_attribute_from_entry, render_templated_string
from SRAMsync.event_handler import EventHandler
from SRAMsync.sramlogger import logger
from SRAMsync.state import State
from SRAMsync.sync_with_sram import ConfigValidationError, PasswordNotFound
from SRAMsync.typing import (
    COmessage,
    EmailNotificationConfig,
    EventHandlerConfig,
    Message,
    MessageContent,
    SMTPconfig,
)


class SMTPclient:
    """Class for handling client side SMTP."""

    _DEFAULT_CIPHERS = (
        "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:"
        "DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:"
        "!eNULL:!MD5"
    )

    def __init__(
        self,
        cfg: SMTPconfig,
        service: str,
        mail_to: str,
        mail_from: str,
        mail_subject: str,
        mail_message: str,
        mail_to_stdout: bool = False,
    ) -> None:
        self.mail_to = mail_to
        self.mail_from = mail_from
        self.mail_subject = render_templated_string(template_string=mail_subject, service=service)
        self.mail_message = mail_message
        self.mail_to_stdout = mail_to_stdout

        if not mail_to_stdout:
            self.server = self.conntect_to_smtp_server(cfg)
            if "login" in cfg or "passwd" in cfg:
                if "login" not in cfg:
                    logger.error("Incomplete SMTP credentials. Need login name as well.")
                elif "passwd" not in cfg:
                    logger.error("Incomplete SMTP credentials. Need passwd as well.")
                else:
                    self.login(login_name=cfg["login"], passwd=cfg["passwd"])

    def __del__(self) -> None:
        if hasattr(self, "server"):
            logger.debug("Disconnecting SMTP server")
            self.server.quit()

    @staticmethod
    def conntect_to_smtp_server(cfg: SMTPconfig) -> smtplib.SMTP:
        """Connect to an SMTP server."""
        msg: str = f"SMTP: connecting to: {cfg['host']}"
        host: str = cfg["host"]
        port: int = 0  # If port not in cfg, then use system default port.

        if "port" in cfg:
            msg = msg + f":{cfg['port']}"
            port = cfg["port"]

        logger.debug(msg)
        try:
            server = smtplib.SMTP(host, port)
            logger.debug("SMTP: connected to SMTP host")
        except ConnectionRefusedError:
            logger.error("Connection to SMTP server %s:%d failed.", host, port)
            sys.exit(1)

        return server

    def login(self, login_name: str, passwd: str) -> None:
        """Log into an SMTP server."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3

        ctx.set_ciphers(self._DEFAULT_CIPHERS)
        ctx.set_default_verify_paths()
        ctx.verify_mode = ssl.CERT_REQUIRED

        logger.debug("SMTP: starttls")
        self.server.starttls(context=ctx)

        logger.debug("SMTP: trying to login")
        self.server.login(user=login_name, password=passwd)
        logger.debug("SMTP: login successful")

    def send_message(self, message: str, service: str) -> None:
        """Send a message through an opened SMTP server."""
        try:
            logger.debug("Sending message")

            msg = EmailMessage()
            msg["to"] = self.mail_to
            msg["from"] = self.mail_from
            msg["subject"] = self.mail_subject
            msg["Date"] = formatdate(localtime=True)
            content = render_templated_string(
                template_string=self.mail_message, service=service, message=message
            )
            msg.set_content(content)

            if not self.mail_to_stdout:
                self.server.send_message(msg)
            else:
                logger.info(click.style(text="Want to sent message:", bold=True, fg="yellow"))
                logger.info(msg)
                logger.info(click.style(text="end-of-message", bold=True, fg="yellow"))

            logger.debug("Message sent")
        except smtplib.SMTPServerDisconnected:
            logger.error("Sending e-mail notifications for has failed. SMTP server has disconnected.")

    def set_output_to_stdout(self):
        """
        Print the mail message to stdout instead of sending it through the
        SMTP server.
        """
        self.mail_to_stdout = True


class EmailNotifications(EventHandler):
    """
    For each emitted event by sync-with-sram produce a message describing the
    event. Messages are collect and sent upon deletion of the
    EmailNotifications object.
    """

    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "collect_events": {"type": "boolean"},
            "aggregate_mails": {"type": "boolean"},
            "report_events": {
                "type": "object",
                "patternProperties": {
                    (
                        "^start-co-processing$|"
                        "^add-new-user$|"
                        "^add-ssh-key$|"
                        "^delete-ssh-key$|"
                        "^delete-ssh-key$|"
                        "^add-group$|"
                        "^remove-group$|"
                        "^add-user-to-group$|"
                        "^start-grace-period-for-user$|"
                        "^remove-user-from-group$|"
                        "^remove-graced-user-from-group$|"
                        "^finalize$"
                    ): {
                        "type": "object",
                        "properties": {"line": {"type": "string"}},
                        "required": ["line"],
                        "optional": ["header"],
                    },
                },
                "additionalProperties": False,
            },
            "smtp": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "login": {"type": "string"},
                },
                "required": ["host"],
                "dependentSchemas": {
                    "login": {
                        "oneOf": [
                            {"properties": {"passwd": {"type": "string"}}, "required": ["passwd"]},
                            {
                                "properties": {"passwd_from_secrets": {"type": "boolean"}},
                                "required": ["passwd_from_secrets"],
                            },
                        ]
                    }
                },
                "dependentRequired": {"passwd": ["login"], "passwd_from_secrets": ["login"]},
            },
            "mail-from": {"type": "string"},
            "mail-to": {"type": "string"},
            "mail-subject": {"type": "string"},
            "mail-message": {"type": "string"},
        },
        "required": ["report_events", "smtp", "mail-from", "mail-to", "mail-subject", "mail-message"],
        "optional": ["collect_events", "aggregate_mails"],
    }

    _DEFAULT_CIPHERS = (
        "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:"
        "DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:"
        "!eNULL:!MD5"
    )

    def __init__(self, service: str, cfg: EventHandlerConfig, state: State, config_path: Path) -> None:
        super().__init__(service=service, cfg=cfg, state=state, cfg_path=config_path)
        try:
            validate(
                schema=self._schema,
                instance=cfg["event_handler_config"],
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )

            # self.mail_to_stdout = "mail-to-stdout" in args
            self.mail_to_stdout = False
            self.cfg = cast(EmailNotificationConfig, cfg["event_handler_config"])
            self.collect_events = cfg["event_handler_config"].get("collect_events", True)

            if "aggregate_mails" in cfg["event_handler_config"]:
                self.aggregate_mails = cfg["event_handler_config"]["aggregate_mails"]
                if not self.collect_events and self.aggregate_mails:
                    logger.warning(
                        "Ignoring value of aggregate_mails, because collect_events is set to False."
                    )
            else:
                self.aggregate_mails = True

            if "passwd_from_secrets" in self.cfg["smtp"]:
                login_name: str = self.cfg["smtp"]["login"]
                host: str = self.cfg["smtp"]["host"]
                self.cfg["smtp"]["passwd"] = cfg["secrets"]["smtp"][host][login_name]

            self.service = service
            self._messages: Message = {}
            self.finalize_message = ""

        except ValidationError as e:
            raise ConfigValidationError(exception=e, path=config_path) from e
        except KeyError as e:
            raise PasswordNotFound(
                f"SMTP password for host {cast(EmailNotificationConfig, cfg['event_handler_config'])['smtp']['host']} not found. "
                "Check your password source."
            ) from e

        self.report_events = self.cfg["report_events"]
        self.msg_content = self.cfg["mail-message"]

    def __del__(self) -> None:
        self.send_queued_messages()

    def get_supported_arguments(self) -> Dict[str, Any]:
        """ """
        options = {
            "mail-to-stdout": {"action": lambda: setattr(self, "mail_to_stdout", True), "type": "bool"},
        }

        return options

    def add_message_to_current_co_group(
        self, co: str, event: str, event_message: str, important: bool = False
    ) -> None:
        """Add the message to the current CO message queue."""
        if co not in self._messages:
            self._messages[co] = {}

        if event not in self._messages[co]:
            self._messages[co][event] = cast(MessageContent, {})
            self._messages[co][event]["important"] = important
            self._messages[co][event]["messages"] = set()

        # The same message might be added multiple times, e.g. adding multiple SSH keys for a user.
        # Using set() automatically filters out double messages.
        self._messages[co][event]["messages"].add(event_message)

        if not self.collect_events:
            self.send_queued_messages()
            #  Cleanup all message except for start-co-processing
            self._messages = {
                ok: {ik: iv}
                for ok, ov in self._messages.items()
                for ik, iv in ov.items()
                if ik == "start-co-processing"
            }

    def send_queued_messages(self) -> None:
        """Send all queued message."""
        message: str = ""

        if "smtp" in self.cfg:
            smtp_client = SMTPclient(
                cfg=self.cfg["smtp"],
                service=self.service,
                mail_to=self.cfg["mail-to"],
                mail_from=self.cfg["mail-from"],
                mail_subject=self.cfg["mail-subject"],
                mail_message=self.cfg["mail-message"],
                mail_to_stdout=self.mail_to_stdout,
            )

            if self.mail_to_stdout:
                smtp_client.set_output_to_stdout()

            self.cleanup_messages()

            for co_messages in self._messages.values():
                message = message + self.render_message(messages=co_messages)

                if message and not self.aggregate_mails:
                    if self.finalize_message:
                        message = message + self.finalize_message

                    message = message.strip()
                    smtp_client.send_message(message=message, service=self.service)
                    message = ""

            if message and self.aggregate_mails:
                if self.finalize_message:
                    message = message + self.finalize_message
                message = message.strip()
                smtp_client.send_message(message=message, service=self.service)

    def cleanup_messages(self) -> None:
        """Clean up some of the messages to make the resulting e-mail a bit easier to read."""
        try:
            self._messages[self.service]["add-group"]["messages"] = set(
                sorted(self._messages[self.service]["add-group"]["messages"])
            )
        except KeyError:
            pass

        try:
            self._messages[self.service]["add-user-to-group"]["messages"] = set(
                sorted(self._messages[self.service]["add-user-to-group"]["messages"])
            )
        except KeyError:
            pass

    def render_message(self, messages: COmessage) -> str:
        """Render a final message for collected event messages."""
        events: list[str] = [k for k, v in messages.items() if v["important"] is True]
        if not events:
            return ""

        final_message = ""
        for event, event_values in messages.items():
            message_part: str = ""
            for line in event_values["messages"]:
                message_part = f"{message_part}{line}\n"
            if event in self.report_events and "header" in self.report_events[event]:
                header: str = cast(str, self.report_events[event]["header"])
                message_part = f"{header}\n{message_part}"

            final_message: str = final_message + message_part

        return final_message

    def process_co_attributes(self, attributes: dict[str, list[bytes]], org: str, co: str) -> None:
        super().process_co_attributes(attributes, org, co)

    def add_event_message(self, co: str, event: str, important: bool = True, **args: Any) -> None:
        """Add an event message and apply formatting to it."""
        if event in self.report_events:
            event_message: str = f"{self.report_events[event]['line']}".format(co=co, **args)
            self.add_message_to_current_co_group(co, event, event_message, important)

    def start_of_co_processing(self, co: str) -> None:
        """Add start event message to the message queue."""
        self.add_event_message(co, event="start-co-processing", important=False)

    def add_new_user(self, entry: dict[str, list[bytes]], **kwargs: str) -> None:
        """Add add-new-user event message to the message queue."""
        try:
            co: str = kwargs["co"]
            groups: str = kwargs["groups"]
            user: str = kwargs["user"]
        except KeyError as e:
            logger.error("Missing(email_notification) argument: %s", e)
            sys.exit(1)

        givenname: str = get_attribute_from_entry(entry=entry, attribute="givenName")
        sn: str = get_attribute_from_entry(entry=entry, attribute="sn")
        mail: str = get_attribute_from_entry(entry=entry, attribute="mail")

        self.add_event_message(
            co=co, event="add-new-user", groups=groups, givenname=givenname, sn=sn, user=user, mail=mail
        )

    def add_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """Add add-shh-key event message to the message queue."""
        self.add_event_message(co, event="add-ssh-key", user=user, key=key)

    def delete_public_ssh_key(self, co: str, user: str, key: str) -> None:
        """Add delete-ssh-key event message to the message queue."""
        self.add_event_message(co, event="delete-ssh-key", user=user, key=key)

    def add_new_groups(self, co: str, groups: List[str], group_attributes: list[str]) -> None:
        """Add add-group event message to the message queue."""
        for group in groups:
            self.add_event_message(co, event="add-group", group=group, attributes=group_attributes)

    def remove_group(self, co: str, group: str, group_attributes: list[str]) -> None:
        """Add remove-group event message to the message queue."""
        self.add_event_message(co, event="remove-group", group=group, attributes=group_attributes)

    def add_user_to_group(self, **kwargs: str) -> None:
        try:
            co: str = kwargs["co"]
            groups: str = kwargs["groups"]
            group_attributes: str = kwargs["group_attributes"]
            user: str = kwargs["user"]
        except KeyError as e:
            logger.error("Missing(email_notification) argument: %s", e)
            sys.exit(1)

        """Add add-user-to-group event message to the message queue."""
        for group in groups:
            self.add_event_message(
                co=co, event="add-user-to-group", group=group, user=user, attributes=group_attributes
            )

    def start_grace_period_for_user(
        self, co: str, group: str, group_attributes: list[str], user: str, duration: timedelta
    ) -> None:
        """The grace period for the users has started."""
        self.add_event_message(
            co,
            event="start-grace-period-for-user",
            group=group,
            attributes=group_attributes,
            user=user,
            duration=duration,
        )

    def remove_user_from_group(self, co: str, group: str, group_attributes: list[str], user: str) -> None:
        """Add remove-user-from-group event message to the message queue."""
        self.add_event_message(
            co=co, event="remove-user-from-group", group=group, user=user, attributes=group_attributes
        )

    def remove_graced_user_from_group(
        self, co: str, group: str, group_attributes: list[str], user: str
    ) -> None:
        """Add remove-grace-users-from-group event message to the message queue."""
        self.add_event_message(
            co=co, event="remove-graced-user-from-group", group=group, user=user, attributes=group_attributes
        )

    def remove_user(self, user: str, state: State) -> None:
        super().remove_user(user, state)

    def finalize(self) -> None:
        """
        Render finalize event message. The finalize event is not associated
        with any CO. It is the very last event to be emitted, just prior to
        finishing the synchronization.
        """
        if "finalize" in self.report_events:
            event_message: str = f"{self.report_events['finalize']['line']}"
            self.finalize_message = event_message
