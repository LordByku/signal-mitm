from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SqlStatement(_message.Message):
    __slots__ = ("statement", "parameters")
    class SqlParameter(_message.Message):
        __slots__ = ("stringParamter", "integerParameter", "doubleParameter", "blobParameter", "nullparameter")
        STRINGPARAMTER_FIELD_NUMBER: _ClassVar[int]
        INTEGERPARAMETER_FIELD_NUMBER: _ClassVar[int]
        DOUBLEPARAMETER_FIELD_NUMBER: _ClassVar[int]
        BLOBPARAMETER_FIELD_NUMBER: _ClassVar[int]
        NULLPARAMETER_FIELD_NUMBER: _ClassVar[int]
        stringParamter: str
        integerParameter: int
        doubleParameter: float
        blobParameter: bytes
        nullparameter: bool
        def __init__(self, stringParamter: _Optional[str] = ..., integerParameter: _Optional[int] = ..., doubleParameter: _Optional[float] = ..., blobParameter: _Optional[bytes] = ..., nullparameter: bool = ...) -> None: ...
    STATEMENT_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    statement: str
    parameters: _containers.RepeatedCompositeFieldContainer[SqlStatement.SqlParameter]
    def __init__(self, statement: _Optional[str] = ..., parameters: _Optional[_Iterable[_Union[SqlStatement.SqlParameter, _Mapping]]] = ...) -> None: ...

class SharedPreference(_message.Message):
    __slots__ = ("file", "key", "value", "booleanValue", "stringSetValue", "isStringSetValue")
    FILE_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOLEANVALUE_FIELD_NUMBER: _ClassVar[int]
    STRINGSETVALUE_FIELD_NUMBER: _ClassVar[int]
    ISSTRINGSETVALUE_FIELD_NUMBER: _ClassVar[int]
    file: str
    key: str
    value: str
    booleanValue: bool
    stringSetValue: _containers.RepeatedScalarFieldContainer[str]
    isStringSetValue: bool
    def __init__(self, file: _Optional[str] = ..., key: _Optional[str] = ..., value: _Optional[str] = ..., booleanValue: bool = ..., stringSetValue: _Optional[_Iterable[str]] = ..., isStringSetValue: bool = ...) -> None: ...

class Attachment(_message.Message):
    __slots__ = ("rowId", "attachmentId", "length")
    ROWID_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTID_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    rowId: int
    attachmentId: int
    length: int
    def __init__(self, rowId: _Optional[int] = ..., attachmentId: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class Sticker(_message.Message):
    __slots__ = ("rowId", "length")
    ROWID_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    rowId: int
    length: int
    def __init__(self, rowId: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class Avatar(_message.Message):
    __slots__ = ("name", "recipientId", "length")
    NAME_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    name: str
    recipientId: str
    length: int
    def __init__(self, name: _Optional[str] = ..., recipientId: _Optional[str] = ..., length: _Optional[int] = ...) -> None: ...

class DatabaseVersion(_message.Message):
    __slots__ = ("version",)
    VERSION_FIELD_NUMBER: _ClassVar[int]
    version: int
    def __init__(self, version: _Optional[int] = ...) -> None: ...

class Header(_message.Message):
    __slots__ = ("iv", "salt", "version")
    IV_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    iv: bytes
    salt: bytes
    version: int
    def __init__(self, iv: _Optional[bytes] = ..., salt: _Optional[bytes] = ..., version: _Optional[int] = ...) -> None: ...

class KeyValue(_message.Message):
    __slots__ = ("key", "blobValue", "booleanValue", "floatValue", "integerValue", "longValue", "stringValue")
    KEY_FIELD_NUMBER: _ClassVar[int]
    BLOBVALUE_FIELD_NUMBER: _ClassVar[int]
    BOOLEANVALUE_FIELD_NUMBER: _ClassVar[int]
    FLOATVALUE_FIELD_NUMBER: _ClassVar[int]
    INTEGERVALUE_FIELD_NUMBER: _ClassVar[int]
    LONGVALUE_FIELD_NUMBER: _ClassVar[int]
    STRINGVALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    blobValue: bytes
    booleanValue: bool
    floatValue: float
    integerValue: int
    longValue: int
    stringValue: str
    def __init__(self, key: _Optional[str] = ..., blobValue: _Optional[bytes] = ..., booleanValue: bool = ..., floatValue: _Optional[float] = ..., integerValue: _Optional[int] = ..., longValue: _Optional[int] = ..., stringValue: _Optional[str] = ...) -> None: ...

class BackupFrame(_message.Message):
    __slots__ = ("header", "statement", "preference", "attachment", "version", "end", "avatar", "sticker", "keyValue")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    STATEMENT_FIELD_NUMBER: _ClassVar[int]
    PREFERENCE_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENT_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    STICKER_FIELD_NUMBER: _ClassVar[int]
    KEYVALUE_FIELD_NUMBER: _ClassVar[int]
    header: Header
    statement: SqlStatement
    preference: SharedPreference
    attachment: Attachment
    version: DatabaseVersion
    end: bool
    avatar: Avatar
    sticker: Sticker
    keyValue: KeyValue
    def __init__(self, header: _Optional[_Union[Header, _Mapping]] = ..., statement: _Optional[_Union[SqlStatement, _Mapping]] = ..., preference: _Optional[_Union[SharedPreference, _Mapping]] = ..., attachment: _Optional[_Union[Attachment, _Mapping]] = ..., version: _Optional[_Union[DatabaseVersion, _Mapping]] = ..., end: bool = ..., avatar: _Optional[_Union[Avatar, _Mapping]] = ..., sticker: _Optional[_Union[Sticker, _Mapping]] = ..., keyValue: _Optional[_Union[KeyValue, _Mapping]] = ...) -> None: ...
