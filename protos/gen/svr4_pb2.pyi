from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Request4(_message.Message):
    __slots__ = ("create", "restore1", "restore2", "remove", "query", "rotate_start", "rotate_commit", "rotate_rollback")
    class Create(_message.Message):
        __slots__ = ("max_tries", "oprf_secretshare", "auth_commitment", "encryption_secretshare", "zero_secretshare", "version")
        MAX_TRIES_FIELD_NUMBER: _ClassVar[int]
        OPRF_SECRETSHARE_FIELD_NUMBER: _ClassVar[int]
        AUTH_COMMITMENT_FIELD_NUMBER: _ClassVar[int]
        ENCRYPTION_SECRETSHARE_FIELD_NUMBER: _ClassVar[int]
        ZERO_SECRETSHARE_FIELD_NUMBER: _ClassVar[int]
        VERSION_FIELD_NUMBER: _ClassVar[int]
        max_tries: int
        oprf_secretshare: bytes
        auth_commitment: bytes
        encryption_secretshare: bytes
        zero_secretshare: bytes
        version: int
        def __init__(self, max_tries: _Optional[int] = ..., oprf_secretshare: _Optional[bytes] = ..., auth_commitment: _Optional[bytes] = ..., encryption_secretshare: _Optional[bytes] = ..., zero_secretshare: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...
    class Restore1(_message.Message):
        __slots__ = ("blinded",)
        BLINDED_FIELD_NUMBER: _ClassVar[int]
        blinded: bytes
        def __init__(self, blinded: _Optional[bytes] = ...) -> None: ...
    class Restore2(_message.Message):
        __slots__ = ("auth_point", "auth_scalar", "version")
        AUTH_POINT_FIELD_NUMBER: _ClassVar[int]
        AUTH_SCALAR_FIELD_NUMBER: _ClassVar[int]
        VERSION_FIELD_NUMBER: _ClassVar[int]
        auth_point: bytes
        auth_scalar: bytes
        version: int
        def __init__(self, auth_point: _Optional[bytes] = ..., auth_scalar: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...
    class Remove(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class Query(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class RotateStart(_message.Message):
        __slots__ = ("version", "oprf_secretshare_delta", "encryption_secretshare_delta")
        VERSION_FIELD_NUMBER: _ClassVar[int]
        OPRF_SECRETSHARE_DELTA_FIELD_NUMBER: _ClassVar[int]
        ENCRYPTION_SECRETSHARE_DELTA_FIELD_NUMBER: _ClassVar[int]
        version: int
        oprf_secretshare_delta: bytes
        encryption_secretshare_delta: bytes
        def __init__(self, version: _Optional[int] = ..., oprf_secretshare_delta: _Optional[bytes] = ..., encryption_secretshare_delta: _Optional[bytes] = ...) -> None: ...
    class RotateCommit(_message.Message):
        __slots__ = ("version",)
        VERSION_FIELD_NUMBER: _ClassVar[int]
        version: int
        def __init__(self, version: _Optional[int] = ...) -> None: ...
    class RotateRollback(_message.Message):
        __slots__ = ("version",)
        VERSION_FIELD_NUMBER: _ClassVar[int]
        version: int
        def __init__(self, version: _Optional[int] = ...) -> None: ...
    CREATE_FIELD_NUMBER: _ClassVar[int]
    RESTORE1_FIELD_NUMBER: _ClassVar[int]
    RESTORE2_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    ROTATE_START_FIELD_NUMBER: _ClassVar[int]
    ROTATE_COMMIT_FIELD_NUMBER: _ClassVar[int]
    ROTATE_ROLLBACK_FIELD_NUMBER: _ClassVar[int]
    create: Request4.Create
    restore1: Request4.Restore1
    restore2: Request4.Restore2
    remove: Request4.Remove
    query: Request4.Query
    rotate_start: Request4.RotateStart
    rotate_commit: Request4.RotateCommit
    rotate_rollback: Request4.RotateRollback
    def __init__(self, create: _Optional[_Union[Request4.Create, _Mapping]] = ..., restore1: _Optional[_Union[Request4.Restore1, _Mapping]] = ..., restore2: _Optional[_Union[Request4.Restore2, _Mapping]] = ..., remove: _Optional[_Union[Request4.Remove, _Mapping]] = ..., query: _Optional[_Union[Request4.Query, _Mapping]] = ..., rotate_start: _Optional[_Union[Request4.RotateStart, _Mapping]] = ..., rotate_commit: _Optional[_Union[Request4.RotateCommit, _Mapping]] = ..., rotate_rollback: _Optional[_Union[Request4.RotateRollback, _Mapping]] = ...) -> None: ...

class Response4(_message.Message):
    __slots__ = ("create", "restore1", "restore2", "remove", "query", "rotate_start", "rotate_commit", "rotate_rollback")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNSET: _ClassVar[Response4.Status]
        OK: _ClassVar[Response4.Status]
        INVALID_REQUEST: _ClassVar[Response4.Status]
        MISSING: _ClassVar[Response4.Status]
        ERROR: _ClassVar[Response4.Status]
        RESTORE1_MISSING: _ClassVar[Response4.Status]
        VERSION_MISMATCH: _ClassVar[Response4.Status]
        NOT_ROTATING: _ClassVar[Response4.Status]
        ALREADY_ROTATING: _ClassVar[Response4.Status]
        MERKLE_FAILURE: _ClassVar[Response4.Status]
        DUPLICATE_VERSION: _ClassVar[Response4.Status]
    UNSET: Response4.Status
    OK: Response4.Status
    INVALID_REQUEST: Response4.Status
    MISSING: Response4.Status
    ERROR: Response4.Status
    RESTORE1_MISSING: Response4.Status
    VERSION_MISMATCH: Response4.Status
    NOT_ROTATING: Response4.Status
    ALREADY_ROTATING: Response4.Status
    MERKLE_FAILURE: Response4.Status
    DUPLICATE_VERSION: Response4.Status
    class Create(_message.Message):
        __slots__ = ("status", "tries_remaining")
        STATUS_FIELD_NUMBER: _ClassVar[int]
        TRIES_REMAINING_FIELD_NUMBER: _ClassVar[int]
        status: Response4.Status
        tries_remaining: int
        def __init__(self, status: _Optional[_Union[Response4.Status, str]] = ..., tries_remaining: _Optional[int] = ...) -> None: ...
    class Restore1(_message.Message):
        __slots__ = ("status", "auth", "tries_remaining")
        class Auth(_message.Message):
            __slots__ = ("element", "version")
            ELEMENT_FIELD_NUMBER: _ClassVar[int]
            VERSION_FIELD_NUMBER: _ClassVar[int]
            element: bytes
            version: int
            def __init__(self, element: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...
        STATUS_FIELD_NUMBER: _ClassVar[int]
        AUTH_FIELD_NUMBER: _ClassVar[int]
        TRIES_REMAINING_FIELD_NUMBER: _ClassVar[int]
        status: Response4.Status
        auth: _containers.RepeatedCompositeFieldContainer[Response4.Restore1.Auth]
        tries_remaining: int
        def __init__(self, status: _Optional[_Union[Response4.Status, str]] = ..., auth: _Optional[_Iterable[_Union[Response4.Restore1.Auth, _Mapping]]] = ..., tries_remaining: _Optional[int] = ...) -> None: ...
    class Restore2(_message.Message):
        __slots__ = ("status", "encryption_secretshare")
        STATUS_FIELD_NUMBER: _ClassVar[int]
        ENCRYPTION_SECRETSHARE_FIELD_NUMBER: _ClassVar[int]
        status: Response4.Status
        encryption_secretshare: bytes
        def __init__(self, status: _Optional[_Union[Response4.Status, str]] = ..., encryption_secretshare: _Optional[bytes] = ...) -> None: ...
    class Remove(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class Query(_message.Message):
        __slots__ = ("status", "tries_remaining", "version", "new_version")
        STATUS_FIELD_NUMBER: _ClassVar[int]
        TRIES_REMAINING_FIELD_NUMBER: _ClassVar[int]
        VERSION_FIELD_NUMBER: _ClassVar[int]
        NEW_VERSION_FIELD_NUMBER: _ClassVar[int]
        status: Response4.Status
        tries_remaining: int
        version: int
        new_version: int
        def __init__(self, status: _Optional[_Union[Response4.Status, str]] = ..., tries_remaining: _Optional[int] = ..., version: _Optional[int] = ..., new_version: _Optional[int] = ...) -> None: ...
    class RotateStart(_message.Message):
        __slots__ = ("status",)
        STATUS_FIELD_NUMBER: _ClassVar[int]
        status: Response4.Status
        def __init__(self, status: _Optional[_Union[Response4.Status, str]] = ...) -> None: ...
    class RotateCommit(_message.Message):
        __slots__ = ("status",)
        STATUS_FIELD_NUMBER: _ClassVar[int]
        status: Response4.Status
        def __init__(self, status: _Optional[_Union[Response4.Status, str]] = ...) -> None: ...
    class RotateRollback(_message.Message):
        __slots__ = ("status",)
        STATUS_FIELD_NUMBER: _ClassVar[int]
        status: Response4.Status
        def __init__(self, status: _Optional[_Union[Response4.Status, str]] = ...) -> None: ...
    CREATE_FIELD_NUMBER: _ClassVar[int]
    RESTORE1_FIELD_NUMBER: _ClassVar[int]
    RESTORE2_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    ROTATE_START_FIELD_NUMBER: _ClassVar[int]
    ROTATE_COMMIT_FIELD_NUMBER: _ClassVar[int]
    ROTATE_ROLLBACK_FIELD_NUMBER: _ClassVar[int]
    create: Response4.Create
    restore1: Response4.Restore1
    restore2: Response4.Restore2
    remove: Response4.Remove
    query: Response4.Query
    rotate_start: Response4.RotateStart
    rotate_commit: Response4.RotateCommit
    rotate_rollback: Response4.RotateRollback
    def __init__(self, create: _Optional[_Union[Response4.Create, _Mapping]] = ..., restore1: _Optional[_Union[Response4.Restore1, _Mapping]] = ..., restore2: _Optional[_Union[Response4.Restore2, _Mapping]] = ..., remove: _Optional[_Union[Response4.Remove, _Mapping]] = ..., query: _Optional[_Union[Response4.Query, _Mapping]] = ..., rotate_start: _Optional[_Union[Response4.RotateStart, _Mapping]] = ..., rotate_commit: _Optional[_Union[Response4.RotateCommit, _Mapping]] = ..., rotate_rollback: _Optional[_Union[Response4.RotateRollback, _Mapping]] = ...) -> None: ...
