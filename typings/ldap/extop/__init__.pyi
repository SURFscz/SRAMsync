"""
This type stub file was generated by pyright.
"""

from ldap import __version__
from ldap.extop.dds import *
from ldap.extop.passwd import PasswordModifyResponse

"""
controls.py - support classes for LDAPv3 extended operations

See https://www.python-ldap.org/ for details.

Description:
The ldap.extop module provides base classes for LDAPv3 extended operations.
Each class provides support for a certain extended operation request and
response.
"""
class ExtendedRequest:
  """
  Generic base class for a LDAPv3 extended operation request

  requestName
      OID as string of the LDAPv3 extended operation request
  requestValue
      value of the LDAPv3 extended operation request
      (here it is the BER-encoded ASN.1 request value)
  """
  def __init__(self, requestName, requestValue) -> None:
    ...
  
  def __repr__(self): # -> str:
    ...
  
  def encodedRequestValue(self): # -> Any:
    """
    returns the BER-encoded ASN.1 request value composed by class attributes
    set before
    """
    ...
  


class ExtendedResponse:
  """
  Generic base class for a LDAPv3 extended operation response

  requestName
      OID as string of the LDAPv3 extended operation response
  encodedResponseValue
      BER-encoded ASN.1 value of the LDAPv3 extended operation response
  """
  def __init__(self, responseName, encodedResponseValue) -> None:
    ...
  
  def __repr__(self): # -> str:
    ...
  
  def decodeResponseValue(self, value):
    """
    decodes the BER-encoded ASN.1 extended operation response value and
    sets the appropriate class attributes
    """
    ...
  


