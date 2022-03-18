"""
Send e-mails for each emited event from the sync-with-sram main loop. For which
events to send email is configurable and also some basic formatting can be
applied.
"""

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate

from jsonschema import ValidationError, validate

from .common import render_templated_string
from .event_handler import EventHandler
from .sramlogger import logger
from .sync_with_sram import ConfigValidationError, PasswordNotFound


class SMTPclient:
    """Class for handling client side SMTP."""

    _DEFAULT_CIPHERS = (
        "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:"
        "DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:"
        "!eNULL:!MD5"
    )

    def __init__(self, cfg, service, mail_to, mail_from, mail_subject, mail_message):
        self.server = self.conntect_to_smtp_server(cfg)
        self.mail_to = mail_to
        self.mail_from = mail_from
        self.mail_subject = render_templated_string(mail_subject, service=service)
        self.mail_message = mail_message

        if "login" in cfg or "passwd" in cfg:
            got_credentials = True
            if not "login" in cfg:
                logger.error("Incomplete SMTP credentials. Need login name as well.")
                got_credentials = False
            if not "passwd" in cfg:
                logger.error("Incomplete SMTP credentials. Need passwd as well.")
                got_credentials = False
            if got_credentials:
                self.login(cfg["login"], cfg["passwd"])

    def __del__(self):
        if hasattr(self, "server"):
            logger.debug("Disconnecting SMTP server")
            self.server.quit()

    @staticmethod
    def conntect_to_smtp_server(cfg):
        """Connect to an SMTP server."""
        msg = f"SMTP: connecting to: {cfg['host']}"
        host = cfg["host"]
        port = 0

        if "port" in cfg:
            msg = msg + f":{cfg['port']}"
            port = cfg["port"]

        logger.debug(msg)
        server = smtplib.SMTP(host, port)
        logger.debug("SMTP: connected to SMTP host")

        return server

    def login(self, login_name, passwd):
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
        self.server.login(login_name, passwd)
        logger.debug("SMTP: login successful")

    def send_message(self, message, service, co):
        """Send a message through an opened SMTP server."""
        try:
            logger.debug("Sending message")

            msg = EmailMessage()
            msg["to"] = self.mail_to
            msg["from"] = self.mail_from
            msg["subject"] = self.mail_subject
            msg["Date"] = formatdate(localtime=True)
            content = render_templated_string(self.mail_message, service=service, co=co, message=message)
            msg.set_content(content)
            self.server.send_message(msg)

            logger.debug("Message sent")
        except smtplib.SMTPServerDisconnected:
            logger.error(f"Sending e-mail notifications for {co} has failed. SMTP server has disconnected.")


class EmailNotifications(EventHandler):
    """
    For each emited event by sync-with-sram produce a message discribing the
    event. Messages are collect and sent upon deletion of the
    EmailNotifications object.
    """

    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "report_events": {
                "type": "object",
                "patternProperties": {
                    "^start$|^add-new-user$|^add-ssh-key$|^delete-ssh-key$|^delete-ssh-key$|^add-group$|^remove-group$|^add-user-to-group$|^remove-user-from-group$|^remove-graced-user-from-group$|^finalize$": {
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
        "required": ["report_events", "mail-from", "mail-to", "mail-subject", "mail-message"],
        "optional": ["smtp"],
    }

    _DEFAULT_CIPHERS = (
        "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:"
        "DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:"
        "!eNULL:!MD5"
    )

    _messages = {}
    _co = "undetermined"

    def __init__(self, service, cfg: dict, config_path) -> None:
        super().__init__(service, cfg, config_path)
        try:
            validate(schema=self._schema, instance=cfg)

            if "passwd_from_secrets" in cfg["smtp"]:
                login_name = cfg["smtp"]["login"]
                host = cfg["smtp"]["host"]
                cfg["smtp"]["passwd"] = cfg["secrets"]["smtp"][host][login_name]

            self.cfg = cfg
            self.service = service
            self.smtp_client = None
        except ValidationError as e:
            raise ConfigValidationError(e, config_path) from e
        except KeyError as e:
            raise PasswordNotFound("Password not found. Check your password source.") from e

        self.report_events = cfg["report_events"]
        self.msg_content = cfg["mail-message"]

    def __del__(self) -> None:
        if hasattr(self, "cfg"):
            self.send_queued_messages()

    def set_current_co_group(self, co) -> None:
        """Set the current CO message queue."""
        self._co = co

    def add_message_to_current_co_group(self, event: str, message: str, discardable: bool = False) -> None:
        """Add the message to the current CO message queue."""
        if self._co not in self._messages:
            self._messages[self._co] = {}

        if event not in self._messages[self._co]:
            self._messages[self._co][event] = {}
            self._messages[self._co][event]["discardable"] = discardable
            self._messages[self._co][event]["messages"] = []

        self._messages[self._co][event]["messages"].append(message)

    def send_queued_messages(self) -> None:
        """Send all queued message."""
        logger.debug("Sending queued messages")
        if "smtp" in self.cfg:
            self.smtp_client = SMTPclient(
                cfg=self.cfg["smtp"],
                service=self.service,
                mail_to=self.cfg["mail-to"],
                mail_from=self.cfg["mail-from"],
                mail_subject=self.cfg["mail-subject"],
                mail_message=self.cfg["mail-message"],
            )

        for co, event_messages in self._messages.items():
            non_discardable_messages = [k for k, v in event_messages.items() if v["discardable"] is False]

            if len(non_discardable_messages) > 0:
                final_message = ""
                for event, message_lines in event_messages.items():
                    message_part = ""
                    for line in message_lines["messages"]:
                        message_part = f"{message_part}{line}\n"
                    if event in self.report_events and "header" in self.report_events[event]:
                        header = self.report_events[event]["header"]
                        message_part = f"{header}\n{message_part}"

                    final_message = final_message + message_part

                self.smtp_client.send_message(final_message[:-1], self.service, co)
            else:
                logger.debug(
                    f"No non discardable messages found. It okay to skip sending e-mail for {co} CO."
                )

        logger.debug("Finished sending queued messages")

    def add_event_message(self, event: str, discardable: bool = False, **args) -> None:
        """Add a event message and apply formatting to it."""
        if event in self.report_events:
            message = f"{self.report_events[event]['line']}".format(**args)
            self.add_message_to_current_co_group(event, message, discardable)

    def start_of_service_processing(self, co: str) -> None:
        """Add start event message to the message queue."""
        self.set_current_co_group(co)
        self.add_event_message("start", discardable=True, co=co)

    def add_new_user(self, group: str, givenname: str, sn: str, user: str, mail: str) -> None:
        """Add add-new-user event message to the message queue."""
        self.add_event_message("add-new-user", group=group, givenname=givenname, sn=sn, user=user, mail=mail)

    def add_public_ssh_key(self, user: str, key: str) -> None:
        """Add add-shh-key event message to the message queue."""
        self.add_event_message("add-ssh-key", user=user, key=key)

    def delete_public_ssh_key(self, user: str, key: str) -> None:
        """Add delete-ssh-key event message to the message queue."""
        self.add_event_message("delete-ssh-key", user=user, key=key)

    def add_new_group(self, group: str, group_attributes: list) -> None:
        """Add add-group event message to the message queue."""
        self.add_event_message("add-group", group=group, attributes=group_attributes)

    def remove_group(self, group: str, group_attributes: list) -> None:
        """Add remove-group event message to the message queue."""
        self.add_event_message("remove-group", group=group, attributes=group_attributes)

    def add_user_to_group(self, group: str, group_attributes: list, user: str) -> None:
        """Add add-user-to-group event message to the message queue."""
        self.add_event_message("add-user-to-group", group=group, user=user, attributes=group_attributes)

    def remove_user_from_group(self, group: str, group_attributes: list, user: str) -> None:
        """Add remove-user-from-group event message to the message queue."""
        self.add_event_message("remove-user-from-group", group=group, user=user, attributes=group_attributes)

    def remove_graced_user_from_group(self, group: str, group_attributes: list, user: str) -> None:
        """Add remove-grace-users-from-group event message to the message queue."""
        self.add_event_message(
            "remove-graced-user-from-group", group=group, user=user, attributes=group_attributes
        )

    def finalize(self) -> None:
        """Add finalize event message to the message queue."""
        self.add_event_message("finalize", discardable=True)
