"""
This type stub file was generated by pyright.
"""

"""Definitions for constants exported by OpenLDAP

This file lists all constants we know about, even those that aren't
available in the OpenLDAP version python-ldap is compiled against.

The information serves two purposes:

- Generate a C header with the constants
- Provide support for building documentation without compiling python-ldap

"""
class Constant:
    """Base class for a definition of an OpenLDAP constant
    """
    def __init__(self, name, optional=..., requirements=..., doc=...) -> None:
        ...
    


class Error(Constant):
    """Definition for an OpenLDAP error code

    This is a constant at the C level; in Python errors are provided as
    exception classes.
    """
    c_template = ...


class Int(Constant):
    """Definition for an OpenLDAP integer constant"""
    c_template = ...


class TLSInt(Int):
    """Definition for a TLS integer constant -- requires HAVE_TLS"""
    def __init__(self, *args, **kwargs) -> None:
        ...
    


class Feature(Constant):
    """Definition for a feature: 0 or 1 based on a C #ifdef

    """
    c_template = ...
    def __init__(self, name, c_feature, **kwargs) -> None:
        ...
    


class Str(Constant):
    c_template = ...


API_2004 = ...
CONSTANTS = ...
def print_header(): # -> None:
    """Print the C header file to standard output"""
    ...

if __name__ == '__main__':
    ...
