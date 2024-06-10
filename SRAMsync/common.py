"""Common functionalities."""

import importlib
import re
from typing import Any, List


class TemplateError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def get_attribute_from_entry(entry: dict[str, list[bytes]], attribute: str) -> str:
    """get the attribute value from entry and convert the value to UTF-8."""
    return entry[attribute][0].decode("UTF-8")


def get_attribute_list_from_entry(entry: dict[str, list[bytes]], attribute: str) -> list[str]:
    """Get the attribute list from entry and convert the values to UTF-8."""
    return [v.decode("UTF-8") for v in entry[attribute]]


def render_templated_string(template_string: str, **kwargs: str) -> str:
    """
    Render a string based on a set of keywords. **kw contains defined keywords
    than can be expanded.
    """
    try:
        return template_string.format(**kwargs)
    except KeyError as e:
        raise TemplateError("Unknow keyword {} in template: {}".format(e, template_string))


def render_templated_string_list(template_strings: List[str], **kwargs: dict[str, str]) -> List[str]:
    """
    Render a string based on a set of keywords. **kw contains defined keywords
    than can be expanded.
    """

    template_list: list[str] = []
    for i in template_strings:
        template_list.append(render_templated_string(i, **kwargs))

    return template_list


def pascal_case_to_snake_case(string: str) -> str:
    """Convert a pascal case string to its snake case equivalent."""
    string = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", string)
    string = re.sub(r"([a-z])([A-Z])", r"\1_\2", string)

    return string.lower()


def deduct_event_handler_class(event_handler_full_name: str) -> Any:
    """
    Deduct the event handler class to import from the given name.
    Names can be e.g.
    - (old style) DummyEventHandler which will be translated to SRA
    """
    if "." in event_handler_full_name:
        # if there is a "." in the name we assume its a full package name
        components = event_handler_full_name.split(".")
        event_handler_class_name = components[-1]
        event_handler_module_name = ".".join(components[0:-1])
    else:
        # default to "SRAMsync" package if nothing special (old behaviour)
        # is specified in the "name" attribute
        event_handler_class_name = event_handler_full_name
        event_handler_module_name = "SRAMsync." + pascal_case_to_snake_case(event_handler_class_name)

    event_handler_module = importlib.import_module(event_handler_module_name)

    return getattr(event_handler_module, event_handler_class_name)
