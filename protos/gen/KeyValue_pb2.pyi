from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class LeastActiveLinkedDevice(_message.Message):
    __slots__ = ("name", "lastActiveTimestamp")
    NAME_FIELD_NUMBER: _ClassVar[int]
    LASTACTIVETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    name: str
    lastActiveTimestamp: int
    def __init__(self, name: _Optional[str] = ..., lastActiveTimestamp: _Optional[int] = ...) -> None: ...
