"""Common functionalities."""
import importlib
import re
from typing import Type


def render_templated_string(template_string: str, **kw: str) -> str:
    """
    Contrain the possible keywords for substutution in a templated string.
    """
    return template_string.format(**kw)


def pascal_case_to_snake_case(string: str) -> str:
    """Convert a pascal case string to its snake case equivalant."""
    string = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", string)
    string = re.sub(r"([a-z])([A-Z])", r"\1_\2", string)

    return string.lower()


def deduct_event_handler_class(event_handler_full_name: str) -> Type:
    """
    Deduct the event handler class to import from the given name. 
    Names can be e.g. 
    - (old style) DummyEventHandler which will be translated to SRA
    """
    if "." in event_handler_full_name:
        # if there is a "." in the name we assume its a full package name
        components = event_handler_full_name.split('.')
        event_handler_class_name = components[-1]
        event_handler_module_name = '.'.join(components[0:-1])       
    else:
        # default to "SRAMsync" package if nothing special (old behaviour)
        # is specified in the "name" attribute
        event_handler_class_name = event_handler_full_name
        event_handler_module_name = "SRAMsync." + pascal_case_to_snake_case(event_handler_class_name)
    
    event_handler_module = importlib.import_module(event_handler_module_name)
    return getattr(event_handler_module, event_handler_class_name)
