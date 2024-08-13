from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class LogicalFingerprint(_message.Message):
    __slots__ = ("content",)
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    content: bytes
    def __init__(self, content: _Optional[bytes] = ...) -> None: ...

class CombinedFingerprints(_message.Message):
    __slots__ = ("version", "local_fingerprint", "remote_fingerprint")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    LOCAL_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    REMOTE_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    version: int
    local_fingerprint: LogicalFingerprint
    remote_fingerprint: LogicalFingerprint
    def __init__(self, version: _Optional[int] = ..., local_fingerprint: _Optional[_Union[LogicalFingerprint, _Mapping]] = ..., remote_fingerprint: _Optional[_Union[LogicalFingerprint, _Mapping]] = ...) -> None: ...
