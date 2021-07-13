import yaml
from jsonschema import validate, ValidationError

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
                    "add": { "type": "string" },
                    "modify": { "type": "string" },
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
                "required": ["add", "modify", "groups"]
            },
            "status_filename": { "type": "string" }
        }
    }

    def __init__(self, config_file):
        try:
            with open(config_file) as f:
                config = yaml.safe_load(f)

            validate(schema=self._schema, instance=config)

            self.config = config
        except ValidationError as e:
            print(e)

    def __getitem__(self, item):
        return self.config[item]
