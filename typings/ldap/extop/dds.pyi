"""
This type stub file was generated by pyright.
"""

from ldap.extop import ExtendedRequest, ExtendedResponse
from pyasn1.type import univ

"""
ldap.extop.dds - Classes for Dynamic Entries extended operations
(see RFC 2589)

See https://www.python-ldap.org/ for details.
"""
class RefreshRequest(ExtendedRequest):
  requestName = ...
  defaultRequestTtl = ...
  class RefreshRequestValue(univ.Sequence):
    componentType = ...
  
  
  def __init__(self, requestName=..., entryName=..., requestTtl=...) -> None:
    ...
  
  def encodedRequestValue(self):
    ...
  


class RefreshResponse(ExtendedResponse):
  responseName = ...
  class RefreshResponseValue(univ.Sequence):
    componentType = ...
  
  
  def decodeResponseValue(self, value): # -> int:
    ...
  


