from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class DeviceName(_message.Message):
    __slots__ = ("ephemeralPublic", "syntheticIv", "ciphertext")
    EPHEMERALPUBLIC_FIELD_NUMBER: _ClassVar[int]
    SYNTHETICIV_FIELD_NUMBER: _ClassVar[int]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    ephemeralPublic: bytes
    syntheticIv: bytes
    ciphertext: bytes
    def __init__(self, ephemeralPublic: _Optional[bytes] = ..., syntheticIv: _Optional[bytes] = ..., ciphertext: _Optional[bytes] = ...) -> None: ...
