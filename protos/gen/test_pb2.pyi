from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class TestEnum(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ZERO: _ClassVar[TestEnum]
    ONE: _ClassVar[TestEnum]
    TWO: _ClassVar[TestEnum]

class TestEnumWithExtraVariants(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ZERO_EXTRA_VARIANTS: _ClassVar[TestEnumWithExtraVariants]
    ONE_EXTRA_VARIANTS: _ClassVar[TestEnumWithExtraVariants]
    TWO_EXTRA_VARIANTS: _ClassVar[TestEnumWithExtraVariants]
    EXTRA_THREE: _ClassVar[TestEnumWithExtraVariants]
    EXTRA_FOUR: _ClassVar[TestEnumWithExtraVariants]
ZERO: TestEnum
ONE: TestEnum
TWO: TestEnum
ZERO_EXTRA_VARIANTS: TestEnumWithExtraVariants
ONE_EXTRA_VARIANTS: TestEnumWithExtraVariants
TWO_EXTRA_VARIANTS: TestEnumWithExtraVariants
EXTRA_THREE: TestEnumWithExtraVariants
EXTRA_FOUR: TestEnumWithExtraVariants

class TestMessage(_message.Message):
    __slots__ = ("oneof_bool", "oneof_message", "string", "int64", "repeated_message", "bytes", "repeated_uint64", "enum", "nested_message", "map")
    class MapEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: TestMessage
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[TestMessage, _Mapping]] = ...) -> None: ...
    ONEOF_BOOL_FIELD_NUMBER: _ClassVar[int]
    ONEOF_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    STRING_FIELD_NUMBER: _ClassVar[int]
    INT64_FIELD_NUMBER: _ClassVar[int]
    REPEATED_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    REPEATED_UINT64_FIELD_NUMBER: _ClassVar[int]
    ENUM_FIELD_NUMBER: _ClassVar[int]
    NESTED_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    MAP_FIELD_NUMBER: _ClassVar[int]
    oneof_bool: bool
    oneof_message: TestMessage
    string: str
    int64: int
    repeated_message: _containers.RepeatedCompositeFieldContainer[TestMessage]
    bytes: bytes
    repeated_uint64: _containers.RepeatedScalarFieldContainer[int]
    enum: TestEnum
    nested_message: TestMessage
    map: _containers.MessageMap[str, TestMessage]
    def __init__(self, oneof_bool: bool = ..., oneof_message: _Optional[_Union[TestMessage, _Mapping]] = ..., string: _Optional[str] = ..., int64: _Optional[int] = ..., repeated_message: _Optional[_Iterable[_Union[TestMessage, _Mapping]]] = ..., bytes: _Optional[bytes] = ..., repeated_uint64: _Optional[_Iterable[int]] = ..., enum: _Optional[_Union[TestEnum, str]] = ..., nested_message: _Optional[_Union[TestMessage, _Mapping]] = ..., map: _Optional[_Mapping[str, TestMessage]] = ...) -> None: ...

class TestMessageWithExtraFields(_message.Message):
    __slots__ = ("oneof_bool", "oneof_message", "oneof_extra_message", "oneof_extra_string", "oneof_extra_int64", "string", "extra_string", "int64", "extra_int64", "repeated_message", "extra_repeated_message", "bytes", "extra_bytes", "repeated_uint64", "extra_repeated_uint64", "enum", "extra_enum", "nested_message", "extra_nested_message", "map", "extra_map")
    class MapEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: TestMessageWithExtraFields
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[TestMessageWithExtraFields, _Mapping]] = ...) -> None: ...
    class ExtraMapEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: TestMessageWithExtraFields
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[TestMessageWithExtraFields, _Mapping]] = ...) -> None: ...
    ONEOF_BOOL_FIELD_NUMBER: _ClassVar[int]
    ONEOF_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ONEOF_EXTRA_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    ONEOF_EXTRA_STRING_FIELD_NUMBER: _ClassVar[int]
    ONEOF_EXTRA_INT64_FIELD_NUMBER: _ClassVar[int]
    STRING_FIELD_NUMBER: _ClassVar[int]
    EXTRA_STRING_FIELD_NUMBER: _ClassVar[int]
    INT64_FIELD_NUMBER: _ClassVar[int]
    EXTRA_INT64_FIELD_NUMBER: _ClassVar[int]
    REPEATED_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    EXTRA_REPEATED_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    EXTRA_BYTES_FIELD_NUMBER: _ClassVar[int]
    REPEATED_UINT64_FIELD_NUMBER: _ClassVar[int]
    EXTRA_REPEATED_UINT64_FIELD_NUMBER: _ClassVar[int]
    ENUM_FIELD_NUMBER: _ClassVar[int]
    EXTRA_ENUM_FIELD_NUMBER: _ClassVar[int]
    NESTED_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    EXTRA_NESTED_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    MAP_FIELD_NUMBER: _ClassVar[int]
    EXTRA_MAP_FIELD_NUMBER: _ClassVar[int]
    oneof_bool: bool
    oneof_message: TestMessageWithExtraFields
    oneof_extra_message: TestMessageWithExtraFields
    oneof_extra_string: str
    oneof_extra_int64: int
    string: str
    extra_string: str
    int64: int
    extra_int64: int
    repeated_message: _containers.RepeatedCompositeFieldContainer[TestMessageWithExtraFields]
    extra_repeated_message: _containers.RepeatedCompositeFieldContainer[TestMessageWithExtraFields]
    bytes: bytes
    extra_bytes: bytes
    repeated_uint64: _containers.RepeatedScalarFieldContainer[int]
    extra_repeated_uint64: _containers.RepeatedScalarFieldContainer[int]
    enum: TestEnumWithExtraVariants
    extra_enum: TestEnumWithExtraVariants
    nested_message: TestMessageWithExtraFields
    extra_nested_message: TestMessageWithExtraFields
    map: _containers.MessageMap[str, TestMessageWithExtraFields]
    extra_map: _containers.MessageMap[str, TestMessageWithExtraFields]
    def __init__(self, oneof_bool: bool = ..., oneof_message: _Optional[_Union[TestMessageWithExtraFields, _Mapping]] = ..., oneof_extra_message: _Optional[_Union[TestMessageWithExtraFields, _Mapping]] = ..., oneof_extra_string: _Optional[str] = ..., oneof_extra_int64: _Optional[int] = ..., string: _Optional[str] = ..., extra_string: _Optional[str] = ..., int64: _Optional[int] = ..., extra_int64: _Optional[int] = ..., repeated_message: _Optional[_Iterable[_Union[TestMessageWithExtraFields, _Mapping]]] = ..., extra_repeated_message: _Optional[_Iterable[_Union[TestMessageWithExtraFields, _Mapping]]] = ..., bytes: _Optional[bytes] = ..., extra_bytes: _Optional[bytes] = ..., repeated_uint64: _Optional[_Iterable[int]] = ..., extra_repeated_uint64: _Optional[_Iterable[int]] = ..., enum: _Optional[_Union[TestEnumWithExtraVariants, str]] = ..., extra_enum: _Optional[_Union[TestEnumWithExtraVariants, str]] = ..., nested_message: _Optional[_Union[TestMessageWithExtraFields, _Mapping]] = ..., extra_nested_message: _Optional[_Union[TestMessageWithExtraFields, _Mapping]] = ..., map: _Optional[_Mapping[str, TestMessageWithExtraFields]] = ..., extra_map: _Optional[_Mapping[str, TestMessageWithExtraFields]] = ...) -> None: ...
