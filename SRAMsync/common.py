"""Common functionalities."""
import re


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
