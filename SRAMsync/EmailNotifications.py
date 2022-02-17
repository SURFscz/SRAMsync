from email import message
from genericpath import exists
import json
import ssl
import smtplib

from email.utils import formatdate
from email.message import EmailMessage

from jsonschema import validate, ValidationError

from .sync_with_sram import ConfigValidationError
from .common import render_templated_string
from .SRAMlogger import logger
from .EventHandler import EventHandler


class SMTPclient:
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
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"Sending e-mail notifications for {co} has failed. SMTP server has disconnected.")


class EmailNotifications(EventHandler):
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
                    "passwd": {"type": "string"},
                },
                "required": ["host"],
                "optional": ["port", "login", "passwd"],
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

    def __init__(self, service, cfg, path):
        try:
            validate(schema=self._schema, instance=cfg)

            self.cfg = cfg
            self.service = service
        except ValidationError as e:
            raise ConfigValidationError(e, path)

        self.report_events = cfg["report_events"]
        self.msg_content = cfg["mail-message"]

    def __del__(self):
        if hasattr(self, "cfg"):
            self.send_queued_messages()

    def set_current_co_group(self, co):
        self._co = co

    def add_message_to_current_co_group(self, event, message):
        if self._co not in self._messages:
            self._messages[self._co] = {}

        if event not in self._messages[self._co]:
            self._messages[self._co][event] = []

        self._messages[self._co][event].append(message)

    def send_queued_messages(self):
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
            final_message = ""
            for event, message_lines in event_messages.items():
                message_line = ""
                for line in message_lines:
                    message_line = f"{message_line}{line}\n"
                if event in self.report_events and "header" in self.report_events[event]:
                    header = self.report_events[event]["header"]
                    message_line = f"{header}\n{message_line}"

                final_message = final_message + message_line

            self.smtp_client.send_message(final_message[:-1], self.service, co)

        logger.debug("Finished sending queued messages")

    def add_event_message(self, event, **args):
        if event in self.report_events:
            message = f"{self.report_events[event]['line']}".format(**args)
            self.add_message_to_current_co_group(event, message)

    def start_of_service_processing(self, co):
        self.set_current_co_group(co)
        self.add_event_message("start", co=co)

    def add_new_user(self, group, givenname, sn, user, mail):
        self.add_event_message("add-new-user", group=group, givenname=givenname, sn=sn, user=user, mail=mail)

    def add_public_ssh_key(self, user, key):
        self.add_event_message("add-ssh-key", user=user, key=key)

    def delete_public_ssh_key(self, user, key):
        self.add_event_message("delete-ssh-key", user=user, key=key)

    def add_new_group(self, group, attributes):
        self.add_event_message("add-group", group=group, attributes=attributes)

    def remove_group(self, group, attributes):
        self.add_event_message("remove-group", group=group, attributes=attributes)

    def add_user_to_group(self, group, user, attributes: list):
        self.add_event_message("add-user-to-group", group=group, user=user, attributes=attributes)

    def remove_user_from_group(self, group, user, attributes: list):
        self.add_event_message("remove-user-from-group", group=group, user=user, attributes=attributes)

    def remove_graced_user_from_group(self, group, user, attributes):
        self.add_event_message("remove-graced-user-from-group", group=group, user=user, attributes=attributes)

    def finalize(self):
        self.add_event_message("finalize")
