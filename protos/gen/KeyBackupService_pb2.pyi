from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Request(_message.Message):
    __slots__ = ("backup", "restore", "delete")
    BACKUP_FIELD_NUMBER: _ClassVar[int]
    RESTORE_FIELD_NUMBER: _ClassVar[int]
    DELETE_FIELD_NUMBER: _ClassVar[int]
    backup: BackupRequest
    restore: RestoreRequest
    delete: DeleteRequest
    def __init__(self, backup: _Optional[_Union[BackupRequest, _Mapping]] = ..., restore: _Optional[_Union[RestoreRequest, _Mapping]] = ..., delete: _Optional[_Union[DeleteRequest, _Mapping]] = ...) -> None: ...

class Response(_message.Message):
    __slots__ = ("backup", "restore", "delete")
    BACKUP_FIELD_NUMBER: _ClassVar[int]
    RESTORE_FIELD_NUMBER: _ClassVar[int]
    DELETE_FIELD_NUMBER: _ClassVar[int]
    backup: BackupResponse
    restore: RestoreResponse
    delete: DeleteResponse
    def __init__(self, backup: _Optional[_Union[BackupResponse, _Mapping]] = ..., restore: _Optional[_Union[RestoreResponse, _Mapping]] = ..., delete: _Optional[_Union[DeleteResponse, _Mapping]] = ...) -> None: ...

class BackupRequest(_message.Message):
    __slots__ = ("serviceId", "backupId", "token", "validFrom", "data", "pin", "tries")
    SERVICEID_FIELD_NUMBER: _ClassVar[int]
    BACKUPID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    VALIDFROM_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    PIN_FIELD_NUMBER: _ClassVar[int]
    TRIES_FIELD_NUMBER: _ClassVar[int]
    serviceId: bytes
    backupId: bytes
    token: bytes
    validFrom: int
    data: bytes
    pin: bytes
    tries: int
    def __init__(self, serviceId: _Optional[bytes] = ..., backupId: _Optional[bytes] = ..., token: _Optional[bytes] = ..., validFrom: _Optional[int] = ..., data: _Optional[bytes] = ..., pin: _Optional[bytes] = ..., tries: _Optional[int] = ...) -> None: ...

class BackupResponse(_message.Message):
    __slots__ = ("status", "token")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        OK: _ClassVar[BackupResponse.Status]
        ALREADY_EXISTS: _ClassVar[BackupResponse.Status]
        NOT_YET_VALID: _ClassVar[BackupResponse.Status]
    OK: BackupResponse.Status
    ALREADY_EXISTS: BackupResponse.Status
    NOT_YET_VALID: BackupResponse.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    status: BackupResponse.Status
    token: bytes
    def __init__(self, status: _Optional[_Union[BackupResponse.Status, str]] = ..., token: _Optional[bytes] = ...) -> None: ...

class RestoreRequest(_message.Message):
    __slots__ = ("serviceId", "backupId", "token", "validFrom", "pin")
    SERVICEID_FIELD_NUMBER: _ClassVar[int]
    BACKUPID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    VALIDFROM_FIELD_NUMBER: _ClassVar[int]
    PIN_FIELD_NUMBER: _ClassVar[int]
    serviceId: bytes
    backupId: bytes
    token: bytes
    validFrom: int
    pin: bytes
    def __init__(self, serviceId: _Optional[bytes] = ..., backupId: _Optional[bytes] = ..., token: _Optional[bytes] = ..., validFrom: _Optional[int] = ..., pin: _Optional[bytes] = ...) -> None: ...

class RestoreResponse(_message.Message):
    __slots__ = ("status", "token", "data", "tries")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        OK: _ClassVar[RestoreResponse.Status]
        TOKEN_MISMATCH: _ClassVar[RestoreResponse.Status]
        NOT_YET_VALID: _ClassVar[RestoreResponse.Status]
        MISSING: _ClassVar[RestoreResponse.Status]
        PIN_MISMATCH: _ClassVar[RestoreResponse.Status]
    OK: RestoreResponse.Status
    TOKEN_MISMATCH: RestoreResponse.Status
    NOT_YET_VALID: RestoreResponse.Status
    MISSING: RestoreResponse.Status
    PIN_MISMATCH: RestoreResponse.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TRIES_FIELD_NUMBER: _ClassVar[int]
    status: RestoreResponse.Status
    token: bytes
    data: bytes
    tries: int
    def __init__(self, status: _Optional[_Union[RestoreResponse.Status, str]] = ..., token: _Optional[bytes] = ..., data: _Optional[bytes] = ..., tries: _Optional[int] = ...) -> None: ...

class DeleteRequest(_message.Message):
    __slots__ = ("serviceId", "backupId")
    SERVICEID_FIELD_NUMBER: _ClassVar[int]
    BACKUPID_FIELD_NUMBER: _ClassVar[int]
    serviceId: bytes
    backupId: bytes
    def __init__(self, serviceId: _Optional[bytes] = ..., backupId: _Optional[bytes] = ...) -> None: ...

class DeleteResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
