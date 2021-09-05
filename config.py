import sys

from jsonschema import validate
import yaml


class ConfigurationError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class Config:
    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "sram": {
                "type": "object",
                "properties": {
                    "uri": {"type": "string"},
                    "basedn": {"type": "string"},
                    "binddn": {"type": "string"},
                    "passwd": {"type": "string"},
                },
                "required": ["uri", "basedn", "binddn", "passwd"],
            },
            "sync": {
                "type": "object",
                "properties": {
                    "servicename": {"type": "string"},
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
                    "generator": {
                        "type": "object",
                        "properties": {
                            "generator_type": {"type": "string"},
                            "event_handler": {"type": "string"},
                            "input": {"type": "object"},
                        },
                        "required": ["generator_type", "event_handler", "input"],
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
                "required": ["servicename", "groups", "generator"],
            },
            "status_filename": {"type": "string"},
            "provisional_status_filename": {"type": "string"},
        },
        "required": ["sram", "sync", "status_filename"],
    }

    def __init__(self, config_file):
        with open(config_file) as f:
            config = yaml.safe_load(f)

        validate(schema=self._schema, instance=config)

        self.config_filename = config_file
        self.config = config
        self._ldap_connector = None

    def __getitem__(self, item):
        return self.config[item]

    def __contains__(self, item):
        return item in self.config

    def getSRAMbasedn(self):
        return self.config["sram"]["basedn"]

    def getLDAPconnector(self):
        if self._ldap_connector:
            return self._ldap_connector
        else:
            raise ConfigurationError("ldap_connection is uninitialized.")

    def setLDAPconnector(self, ldap_connector):
        self._ldap_connector = ldap_connector

    def setEventHandler(self, event_handler):
        self.event_handler = event_handler

    def find_line_containing_element(self, *elements):
        with open(self.config_filename) as config:
            line_number = 0
            for element in elements:
                line = config.readline()
                line_number = line_number + 1
                while element not in line:
                    line = config.readline()
                    line_number = line_number + 1
                    if not line:
                        break
        return line_number, line.rstrip()
