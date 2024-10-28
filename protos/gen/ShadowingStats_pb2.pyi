from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class Snapshot(_message.Message):
    __slots__ = ("requestsCompared", "failures", "badStatuses", "reconnects", "lastNotified")
    REQUESTSCOMPARED_FIELD_NUMBER: _ClassVar[int]
    FAILURES_FIELD_NUMBER: _ClassVar[int]
    BADSTATUSES_FIELD_NUMBER: _ClassVar[int]
    RECONNECTS_FIELD_NUMBER: _ClassVar[int]
    LASTNOTIFIED_FIELD_NUMBER: _ClassVar[int]
    requestsCompared: int
    failures: int
    badStatuses: int
    reconnects: int
    lastNotified: int
    def __init__(self, requestsCompared: _Optional[int] = ..., failures: _Optional[int] = ..., badStatuses: _Optional[int] = ..., reconnects: _Optional[int] = ..., lastNotified: _Optional[int] = ...) -> None: ...
