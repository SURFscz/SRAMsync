from distutils.command.config import config
import importlib
from datetime import datetime
import json
from re import I
from jsonschema import validate, ValidationError

from .sync_with_sram import ConfigValidationError
from .common import render_templated_string
from .sramlogger import logger
from .EventHandler import EventHandler
from .CuaScriptGenerator import CuaScriptGenerator


class CbaScriptGenerator(CuaScriptGenerator):
    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "cba_account": {"type": "string"},
            "cua_config": {"type": "object"},
        },
        "required": ["cba_account", "cua_config"],
    }

    def __init__(self, service, cfg, path):
        try:
            validate(schema=CbaScriptGenerator._schema, instance=cfg)
            super().__init__(service, cfg["cua_config"], path)
        except ConfigValidationError as e:
            raise e
        except ValidationError as e:
            raise ConfigValidationError(e, path) from e
