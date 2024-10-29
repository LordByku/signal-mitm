from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class LeastActiveLinkedDevice(_message.Message):
    __slots__ = ("name", "lastActiveTimestamp")
    NAME_FIELD_NUMBER: _ClassVar[int]
    LASTACTIVETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    name: str
    lastActiveTimestamp: int
    def __init__(self, name: _Optional[str] = ..., lastActiveTimestamp: _Optional[int] = ...) -> None: ...

class ArchiveUploadProgressState(_message.Message):
    __slots__ = ("state", "completedAttachments", "totalAttachments")
    class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        None: _ClassVar[ArchiveUploadProgressState.State]
        BackingUpMessages: _ClassVar[ArchiveUploadProgressState.State]
        UploadingMessages: _ClassVar[ArchiveUploadProgressState.State]
        UploadingAttachments: _ClassVar[ArchiveUploadProgressState.State]
    None: ArchiveUploadProgressState.State
    BackingUpMessages: ArchiveUploadProgressState.State
    UploadingMessages: ArchiveUploadProgressState.State
    UploadingAttachments: ArchiveUploadProgressState.State
    STATE_FIELD_NUMBER: _ClassVar[int]
    COMPLETEDATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    TOTALATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    state: ArchiveUploadProgressState.State
    completedAttachments: int
    totalAttachments: int
    def __init__(self, state: _Optional[_Union[ArchiveUploadProgressState.State, str]] = ..., completedAttachments: _Optional[int] = ..., totalAttachments: _Optional[int] = ...) -> None: ...
