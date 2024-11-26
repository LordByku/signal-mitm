from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Trace(_message.Message):
    __slots__ = ("packet",)
    PACKET_FIELD_NUMBER: _ClassVar[int]
    packet: _containers.RepeatedCompositeFieldContainer[TracePacket]
    def __init__(self, packet: _Optional[_Iterable[_Union[TracePacket, _Mapping]]] = ...) -> None: ...

class TracePacket(_message.Message):
    __slots__ = ("timestamp", "timestamp_clock_id", "track_event", "track_descriptor", "synchronization_marker", "trusted_packet_sequence_id")
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_CLOCK_ID_FIELD_NUMBER: _ClassVar[int]
    TRACK_EVENT_FIELD_NUMBER: _ClassVar[int]
    TRACK_DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    SYNCHRONIZATION_MARKER_FIELD_NUMBER: _ClassVar[int]
    TRUSTED_PACKET_SEQUENCE_ID_FIELD_NUMBER: _ClassVar[int]
    timestamp: int
    timestamp_clock_id: int
    track_event: TrackEvent
    track_descriptor: TrackDescriptor
    synchronization_marker: bytes
    trusted_packet_sequence_id: int
    def __init__(self, timestamp: _Optional[int] = ..., timestamp_clock_id: _Optional[int] = ..., track_event: _Optional[_Union[TrackEvent, _Mapping]] = ..., track_descriptor: _Optional[_Union[TrackDescriptor, _Mapping]] = ..., synchronization_marker: _Optional[bytes] = ..., trusted_packet_sequence_id: _Optional[int] = ...) -> None: ...

class TrackEvent(_message.Message):
    __slots__ = ("category_iids", "categories", "debug_annotations", "name_iid", "name", "type", "track_uuid", "counter_value", "timestamp_delta_us", "timestamp_absolute_us", "thread_time_delta_us", "thread_time_absolute_us")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        TYPE_UNSPECIFIED: _ClassVar[TrackEvent.Type]
        TYPE_SLICE_BEGIN: _ClassVar[TrackEvent.Type]
        TYPE_SLICE_END: _ClassVar[TrackEvent.Type]
        TYPE_INSTANT: _ClassVar[TrackEvent.Type]
        TYPE_COUNTER: _ClassVar[TrackEvent.Type]
    TYPE_UNSPECIFIED: TrackEvent.Type
    TYPE_SLICE_BEGIN: TrackEvent.Type
    TYPE_SLICE_END: TrackEvent.Type
    TYPE_INSTANT: TrackEvent.Type
    TYPE_COUNTER: TrackEvent.Type
    CATEGORY_IIDS_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    DEBUG_ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    NAME_IID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    TRACK_UUID_FIELD_NUMBER: _ClassVar[int]
    COUNTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_DELTA_US_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_ABSOLUTE_US_FIELD_NUMBER: _ClassVar[int]
    THREAD_TIME_DELTA_US_FIELD_NUMBER: _ClassVar[int]
    THREAD_TIME_ABSOLUTE_US_FIELD_NUMBER: _ClassVar[int]
    category_iids: _containers.RepeatedScalarFieldContainer[int]
    categories: _containers.RepeatedScalarFieldContainer[str]
    debug_annotations: _containers.RepeatedCompositeFieldContainer[DebugAnnotation]
    name_iid: int
    name: str
    type: TrackEvent.Type
    track_uuid: int
    counter_value: int
    timestamp_delta_us: int
    timestamp_absolute_us: int
    thread_time_delta_us: int
    thread_time_absolute_us: int
    def __init__(self, category_iids: _Optional[_Iterable[int]] = ..., categories: _Optional[_Iterable[str]] = ..., debug_annotations: _Optional[_Iterable[_Union[DebugAnnotation, _Mapping]]] = ..., name_iid: _Optional[int] = ..., name: _Optional[str] = ..., type: _Optional[_Union[TrackEvent.Type, str]] = ..., track_uuid: _Optional[int] = ..., counter_value: _Optional[int] = ..., timestamp_delta_us: _Optional[int] = ..., timestamp_absolute_us: _Optional[int] = ..., thread_time_delta_us: _Optional[int] = ..., thread_time_absolute_us: _Optional[int] = ...) -> None: ...

class TrackDescriptor(_message.Message):
    __slots__ = ("uuid", "parent_uuid", "name", "thread", "counter")
    UUID_FIELD_NUMBER: _ClassVar[int]
    PARENT_UUID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    THREAD_FIELD_NUMBER: _ClassVar[int]
    COUNTER_FIELD_NUMBER: _ClassVar[int]
    uuid: int
    parent_uuid: int
    name: str
    thread: ThreadDescriptor
    counter: CounterDescriptor
    def __init__(self, uuid: _Optional[int] = ..., parent_uuid: _Optional[int] = ..., name: _Optional[str] = ..., thread: _Optional[_Union[ThreadDescriptor, _Mapping]] = ..., counter: _Optional[_Union[CounterDescriptor, _Mapping]] = ...) -> None: ...

class ThreadDescriptor(_message.Message):
    __slots__ = ("pid", "tid", "thread_name")
    PID_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    THREAD_NAME_FIELD_NUMBER: _ClassVar[int]
    pid: int
    tid: int
    thread_name: str
    def __init__(self, pid: _Optional[int] = ..., tid: _Optional[int] = ..., thread_name: _Optional[str] = ...) -> None: ...

class CounterDescriptor(_message.Message):
    __slots__ = ("type", "categories", "unit", "unit_multiplier", "is_incremental")
    class BuiltinCounterType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        COUNTER_UNSPECIFIED: _ClassVar[CounterDescriptor.BuiltinCounterType]
        COUNTER_THREAD_TIME_NS: _ClassVar[CounterDescriptor.BuiltinCounterType]
        COUNTER_THREAD_INSTRUCTION_COUNT: _ClassVar[CounterDescriptor.BuiltinCounterType]
    COUNTER_UNSPECIFIED: CounterDescriptor.BuiltinCounterType
    COUNTER_THREAD_TIME_NS: CounterDescriptor.BuiltinCounterType
    COUNTER_THREAD_INSTRUCTION_COUNT: CounterDescriptor.BuiltinCounterType
    class Unit(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNIT_UNSPECIFIED: _ClassVar[CounterDescriptor.Unit]
        UNIT_TIME_NS: _ClassVar[CounterDescriptor.Unit]
        UNIT_COUNT: _ClassVar[CounterDescriptor.Unit]
        UNIT_SIZE_BYTES: _ClassVar[CounterDescriptor.Unit]
    UNIT_UNSPECIFIED: CounterDescriptor.Unit
    UNIT_TIME_NS: CounterDescriptor.Unit
    UNIT_COUNT: CounterDescriptor.Unit
    UNIT_SIZE_BYTES: CounterDescriptor.Unit
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    UNIT_FIELD_NUMBER: _ClassVar[int]
    UNIT_MULTIPLIER_FIELD_NUMBER: _ClassVar[int]
    IS_INCREMENTAL_FIELD_NUMBER: _ClassVar[int]
    type: CounterDescriptor.BuiltinCounterType
    categories: _containers.RepeatedScalarFieldContainer[str]
    unit: CounterDescriptor.Unit
    unit_multiplier: int
    is_incremental: bool
    def __init__(self, type: _Optional[_Union[CounterDescriptor.BuiltinCounterType, str]] = ..., categories: _Optional[_Iterable[str]] = ..., unit: _Optional[_Union[CounterDescriptor.Unit, str]] = ..., unit_multiplier: _Optional[int] = ..., is_incremental: bool = ...) -> None: ...

class DebugAnnotation(_message.Message):
    __slots__ = ("name_iid", "name", "bool_value", "uint_value", "int_value", "double_value", "string_value", "pointer_value", "nested_value")
    class NestedValue(_message.Message):
        __slots__ = ("nested_type", "dict_keys", "dict_values", "array_values", "int_value", "double_value", "bool_value", "string_value")
        class NestedType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNSPECIFIED: _ClassVar[DebugAnnotation.NestedValue.NestedType]
            DICT: _ClassVar[DebugAnnotation.NestedValue.NestedType]
            ARRAY: _ClassVar[DebugAnnotation.NestedValue.NestedType]
        UNSPECIFIED: DebugAnnotation.NestedValue.NestedType
        DICT: DebugAnnotation.NestedValue.NestedType
        ARRAY: DebugAnnotation.NestedValue.NestedType
        NESTED_TYPE_FIELD_NUMBER: _ClassVar[int]
        DICT_KEYS_FIELD_NUMBER: _ClassVar[int]
        DICT_VALUES_FIELD_NUMBER: _ClassVar[int]
        ARRAY_VALUES_FIELD_NUMBER: _ClassVar[int]
        INT_VALUE_FIELD_NUMBER: _ClassVar[int]
        DOUBLE_VALUE_FIELD_NUMBER: _ClassVar[int]
        BOOL_VALUE_FIELD_NUMBER: _ClassVar[int]
        STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
        nested_type: DebugAnnotation.NestedValue.NestedType
        dict_keys: _containers.RepeatedScalarFieldContainer[str]
        dict_values: _containers.RepeatedCompositeFieldContainer[DebugAnnotation.NestedValue]
        array_values: _containers.RepeatedCompositeFieldContainer[DebugAnnotation.NestedValue]
        int_value: int
        double_value: float
        bool_value: bool
        string_value: str
        def __init__(self, nested_type: _Optional[_Union[DebugAnnotation.NestedValue.NestedType, str]] = ..., dict_keys: _Optional[_Iterable[str]] = ..., dict_values: _Optional[_Iterable[_Union[DebugAnnotation.NestedValue, _Mapping]]] = ..., array_values: _Optional[_Iterable[_Union[DebugAnnotation.NestedValue, _Mapping]]] = ..., int_value: _Optional[int] = ..., double_value: _Optional[float] = ..., bool_value: bool = ..., string_value: _Optional[str] = ...) -> None: ...
    NAME_IID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    BOOL_VALUE_FIELD_NUMBER: _ClassVar[int]
    UINT_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_VALUE_FIELD_NUMBER: _ClassVar[int]
    DOUBLE_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    POINTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    NESTED_VALUE_FIELD_NUMBER: _ClassVar[int]
    name_iid: int
    name: str
    bool_value: bool
    uint_value: int
    int_value: int
    double_value: float
    string_value: str
    pointer_value: int
    nested_value: DebugAnnotation.NestedValue
    def __init__(self, name_iid: _Optional[int] = ..., name: _Optional[str] = ..., bool_value: bool = ..., uint_value: _Optional[int] = ..., int_value: _Optional[int] = ..., double_value: _Optional[float] = ..., string_value: _Optional[str] = ..., pointer_value: _Optional[int] = ..., nested_value: _Optional[_Union[DebugAnnotation.NestedValue, _Mapping]] = ...) -> None: ...
