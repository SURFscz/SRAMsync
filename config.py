import sys

import yaml
from jsonschema import validate, ValidationError


class ConfigurationError(Exception):
    def __init__(self, message):
        self.message = message
        supeer().__init__(self.message)


class Config():
    _schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "ldap": {
                "type": "object",
                "properties": {
                    "uri": { "type": "string" },
                    "basedn": { "type": "string" },
                    "binddn": { "type": "string" },
                    "passwd": { "type": "string" }
                },
                "required": ["uri", "basedn", "binddn", "passwd"]
            },
            "cua": {
                "type": "object",
                "properties": {
                    "add_user": { "type": "string" },
                    "modify_user": { "type": "string" },
                    "groups": { "type": "array" },
                    "grace": {
                        "type": "object",
                        "patternProperties": {
                            "sram-*": {
                                "type": "object",
                                "properties": {
                                    "grace_period": { "type": "number" }
                                }
                            }
                        },
                        "minProperties": 1,
                        "additionalProperties": False
                    }
                },
                "required": ["add_user", "modify_user", "groups"]
            },
            "status_filename": { "type": "string" }
        }
    }


    def __init__(self, config_file):
        try:
            with open(config_file) as f:
                config = yaml.safe_load(f)

            validate(schema=self._schema, instance=config)

            self.config_filename = config_file
            self.config = config
            self._ldap_connector = None
            self._output_fd = sys.stdout
        except ValidationError as e:
            print(e)


    def __getitem__(self, item):
        return self.config[item]


    def getSRAMbasedn(self):
        return self.config['ldap']['basedn']


    def getLDAPconnector(self):
        if self._ldap_connector:
            return self._ldap_connector
        else:
            raise ConfigurationError('ldap_connection is uninitialized.')


    def getOutputDescriptor(self):
        return self._output_fd


    def setLDAPconnector(self, ldap_connector):
        self._ldap_connector = ldap_connector


    def setOutputDescriptor(self, output_fd):
        self._output_fd = output_fd


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
