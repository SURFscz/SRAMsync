"""
  Configuration definition and validating. The config class defines
  the main configuration. EventHandler classes may extent the
  configuration.
"""
import importlib
import json
from typing import Any

import yaml
from jsonschema import validate
from ldap import ldapobject

from .common import pascal_case_to_snake_case
from .event_handler import EventHandler


class ConfigurationError(Exception):
    """Exception class representing configuration errors."""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class Config:
    """
    Class for defining and handling the configuration for sync-with-sram.
    The configuration file must be in JSON and a JSON schema is defined
    and used for validating a configuration file.
    """

    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "service": {"type": "string"},
            "secrets": {
                "type": "object",
                "properties": {"file": {"type": "string"}},
                "required": ["file"],
                "additionalProperties": False,
            },
            "sram": {
                "type": "object",
                "properties": {
                    "uri": {"type": "string"},
                    "basedn": {"type": "string"},
                    "binddn": {"type": "string"},
                    "passwd": {"type": "string"},
                    "passwd_from_file": {"type": "boolean"},
                },
                "required": ["uri", "basedn", "binddn"],
                "not": {"required": ["passwd", "passwd_from_file"]},
            },
            "sync": {
                "type": "object",
                "properties": {
                    "users": {
                        "type": "object",
                        "properties": {"rename_user": {"type": "string"}},
                        "required": ["rename_user"],
                        "additionalProperties": False,
                    },
                    "groups": {
                        "type": "object",
                        "patternProperties": {
                            ".*": {
                                "type": "object",
                                "properties": {
                                    "attributes": {"type": "array"},
                                    "destination": {"type": "string"},
                                },
                                "required": ["attributes", "destination"],
                            },
                        },
                    },
                    "event_handler": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "config": {"type": "object"},
                        },
                        "required": ["name"],
                        "additionalProperties": False,
                    },
                    "grace": {
                        "type": "object",
                        "patternProperties": {
                            ".*": {
                                "type": "object",
                                "properties": {"grace_period": {"type": "number"}},
                                "required": ["grace_period"],
                            }
                        },
                        "minProperties": 1,
                        "additionalProperties": False,
                    },
                },
                "required": ["users", "groups", "event_handler"],
            },
            "status_filename": {"type": "string"},
            "provisional_status_filename": {"type": "string"},
        },
        "required": ["service", "sram", "sync", "status_filename"],
        "additionalProperties": False,
    }

    def __init__(self, config_file: str) -> None:
        with open(config_file) as fd:
            config = yaml.safe_load(fd)

        validate(schema=self._schema, instance=config)

        self.config_filename = config_file
        self.config = config
        self._ldap_connector = None

        self.secrets = {}
        if "secrets" in config:
            with open(config["secrets"]["file"]) as fd:
                self.secrets = json.load(fd)

        self.event_handler = self.get_event_handler()

    def __getitem__(self, item: str) -> Any:
        return self.config[item]

    def __contains__(self, item: str) -> bool:
        return item in self.config

    def get_event_handler(self) -> EventHandler:
        """
        Dynamically load the configured class from the configuration. If the class
        expects a configuration extraxt that from the configuration and pass it
        along at instansiation time. Put the status_filename and the optional
        provisional_status_filename in the class configuration.
        """

        event_handler_class_name = self.config["sync"]["event_handler"]["name"]
        event_handler_module_name = pascal_case_to_snake_case(event_handler_class_name)
        event_handler_module = importlib.import_module(f"SRAMsync.{event_handler_module_name}")
        event_handler_class = getattr(event_handler_module, event_handler_class_name)

        handler_cfg = {}
        if "config" in self.config["sync"]["event_handler"]:
            handler_cfg = self.config["sync"]["event_handler"]["config"]

        handler_cfg.update({"status_filename": self.config["status_filename"]})

        if "provisional_status_filename" in self.config:
            handler_cfg.update({"provisional_status_filename": self.config["provisional_status_filename"]})

        if hasattr(self, "secrets"):
            handler_cfg["secrets"] = self.secrets

        event_handler_instance = event_handler_class(
            self.config["service"], handler_cfg, ["sync", "event_handler", "config"]
        )

        return event_handler_instance

    def get_sram_basedn(self) -> str:
        """Get the base DN"""
        return self.config["sram"]["basedn"]

    def get_ldap_connector(self) -> ldapobject.LDAPObject:
        """Get the LDAP connector."""
        if self._ldap_connector:
            return self._ldap_connector

        raise ConfigurationError("ldap_connection is uninitialized.")

    def set_set_ldap_connector(self, ldap_connector: ldapobject.LDAPObject) -> None:
        """Set the LDAP connector."""
        self._ldap_connector = ldap_connector

    def set_event_handler(self, event_handler: EventHandler) -> None:
        """Set the event handler."""
        self.event_handler = event_handler
