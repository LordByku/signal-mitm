from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class UsernameData(_message.Message):
    __slots__ = ("username", "padding")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PADDING_FIELD_NUMBER: _ClassVar[int]
    username: str
    padding: bytes
    def __init__(self, username: _Optional[str] = ..., padding: _Optional[bytes] = ...) -> None: ...
