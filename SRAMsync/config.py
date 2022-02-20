"""
  Configuration definition and validating. The config class defines
  the main configuration. EventHandler classes may extent the
  configuration.
"""

from jsonschema import validate
import yaml


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
            "sram": {
                "type": "object",
                "properties": {
                    "uri": {"type": "string"},
                    "basedn": {"type": "string"},
                    "binddn": {"type": "string"},
                },
                "required": ["uri", "basedn", "binddn"],
                "not": {"required": ["passwd", "passwd_file"]},
            },
            "sync": {
                "type": "object",
                "properties": {
                    "users": {
                        "type": "object",
                        "properties": {"rename_user": {"type": "string"}},
                        "required": ["rename_user"],
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
                        "optional": ["config"],
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
    }

    def __init__(self, config_file):
        with open(config_file) as fd:
            config = yaml.safe_load(fd)

        validate(schema=self._schema, instance=config)

        self.config_filename = config_file
        self.config = config
        self._ldap_connector = None
        self.event_handler = None

    def __getitem__(self, item):
        return self.config[item]

    def __contains__(self, item):
        return item in self.config

    def get_sram_basedn(self):
        """Get the base DN"""
        return self.config["sram"]["basedn"]

    def get_ldap_connector(self):
        """Get the LDAP connector."""
        if self._ldap_connector:
            return self._ldap_connector

        raise ConfigurationError("ldap_connection is uninitialized.")

    def set_set_ldap_connector(self, ldap_connector):
        """Set the LDAP connector."""
        self._ldap_connector = ldap_connector

    def set_event_handler(self, event_handler):
        """Set the event handler."""
        self.event_handler = event_handler
