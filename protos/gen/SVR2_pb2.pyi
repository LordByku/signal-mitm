from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Request(_message.Message):
    __slots__ = ("backup", "expose", "restore", "delete")
    BACKUP_FIELD_NUMBER: _ClassVar[int]
    EXPOSE_FIELD_NUMBER: _ClassVar[int]
    RESTORE_FIELD_NUMBER: _ClassVar[int]
    DELETE_FIELD_NUMBER: _ClassVar[int]
    backup: BackupRequest
    expose: ExposeRequest
    restore: RestoreRequest
    delete: DeleteRequest
    def __init__(self, backup: _Optional[_Union[BackupRequest, _Mapping]] = ..., expose: _Optional[_Union[ExposeRequest, _Mapping]] = ..., restore: _Optional[_Union[RestoreRequest, _Mapping]] = ..., delete: _Optional[_Union[DeleteRequest, _Mapping]] = ...) -> None: ...

class Response(_message.Message):
    __slots__ = ("backup", "expose", "restore", "delete")
    BACKUP_FIELD_NUMBER: _ClassVar[int]
    EXPOSE_FIELD_NUMBER: _ClassVar[int]
    RESTORE_FIELD_NUMBER: _ClassVar[int]
    DELETE_FIELD_NUMBER: _ClassVar[int]
    backup: BackupResponse
    expose: ExposeResponse
    restore: RestoreResponse
    delete: DeleteResponse
    def __init__(self, backup: _Optional[_Union[BackupResponse, _Mapping]] = ..., expose: _Optional[_Union[ExposeResponse, _Mapping]] = ..., restore: _Optional[_Union[RestoreResponse, _Mapping]] = ..., delete: _Optional[_Union[DeleteResponse, _Mapping]] = ...) -> None: ...

class BackupRequest(_message.Message):
    __slots__ = ("data", "pin", "maxTries")
    DATA_FIELD_NUMBER: _ClassVar[int]
    PIN_FIELD_NUMBER: _ClassVar[int]
    MAXTRIES_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    pin: bytes
    maxTries: int
    def __init__(self, data: _Optional[bytes] = ..., pin: _Optional[bytes] = ..., maxTries: _Optional[int] = ...) -> None: ...

class BackupResponse(_message.Message):
    __slots__ = ("status",)
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNSET: _ClassVar[BackupResponse.Status]
        OK: _ClassVar[BackupResponse.Status]
        REQUEST_INVALID: _ClassVar[BackupResponse.Status]
    UNSET: BackupResponse.Status
    OK: BackupResponse.Status
    REQUEST_INVALID: BackupResponse.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: BackupResponse.Status
    def __init__(self, status: _Optional[_Union[BackupResponse.Status, str]] = ...) -> None: ...

class RestoreRequest(_message.Message):
    __slots__ = ("pin",)
    PIN_FIELD_NUMBER: _ClassVar[int]
    pin: bytes
    def __init__(self, pin: _Optional[bytes] = ...) -> None: ...

class RestoreResponse(_message.Message):
    __slots__ = ("status", "data", "tries")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNSET: _ClassVar[RestoreResponse.Status]
        OK: _ClassVar[RestoreResponse.Status]
        MISSING: _ClassVar[RestoreResponse.Status]
        PIN_MISMATCH: _ClassVar[RestoreResponse.Status]
        REQUEST_INVALID: _ClassVar[RestoreResponse.Status]
    UNSET: RestoreResponse.Status
    OK: RestoreResponse.Status
    MISSING: RestoreResponse.Status
    PIN_MISMATCH: RestoreResponse.Status
    REQUEST_INVALID: RestoreResponse.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TRIES_FIELD_NUMBER: _ClassVar[int]
    status: RestoreResponse.Status
    data: bytes
    tries: int
    def __init__(self, status: _Optional[_Union[RestoreResponse.Status, str]] = ..., data: _Optional[bytes] = ..., tries: _Optional[int] = ...) -> None: ...

class DeleteRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeleteResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ExposeRequest(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class ExposeResponse(_message.Message):
    __slots__ = ("status",)
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNSET: _ClassVar[ExposeResponse.Status]
        OK: _ClassVar[ExposeResponse.Status]
        ERROR: _ClassVar[ExposeResponse.Status]
    UNSET: ExposeResponse.Status
    OK: ExposeResponse.Status
    ERROR: ExposeResponse.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: ExposeResponse.Status
    def __init__(self, status: _Optional[_Union[ExposeResponse.Status, str]] = ...) -> None: ...
