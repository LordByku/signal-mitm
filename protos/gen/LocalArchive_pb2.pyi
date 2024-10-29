from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class Metadata(_message.Message):
    __slots__ = ("version",)
    VERSION_FIELD_NUMBER: _ClassVar[int]
    version: int
    def __init__(self, version: _Optional[int] = ...) -> None: ...

class FilesFrame(_message.Message):
    __slots__ = ("mediaName",)
    MEDIANAME_FIELD_NUMBER: _ClassVar[int]
    mediaName: str
    def __init__(self, mediaName: _Optional[str] = ...) -> None: ...
