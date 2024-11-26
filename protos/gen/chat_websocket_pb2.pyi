from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class WebSocketRequestMessage(_message.Message):
    __slots__ = ("verb", "path", "body", "headers", "id")
    VERB_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    verb: str
    path: str
    body: bytes
    headers: _containers.RepeatedScalarFieldContainer[str]
    id: int
    def __init__(self, verb: _Optional[str] = ..., path: _Optional[str] = ..., body: _Optional[bytes] = ..., headers: _Optional[_Iterable[str]] = ..., id: _Optional[int] = ...) -> None: ...

class WebSocketResponseMessage(_message.Message):
    __slots__ = ("id", "status", "message", "headers", "body")
    ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    id: int
    status: int
    message: str
    headers: _containers.RepeatedScalarFieldContainer[str]
    body: bytes
    def __init__(self, id: _Optional[int] = ..., status: _Optional[int] = ..., message: _Optional[str] = ..., headers: _Optional[_Iterable[str]] = ..., body: _Optional[bytes] = ...) -> None: ...

class WebSocketMessage(_message.Message):
    __slots__ = ("type", "request", "response")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[WebSocketMessage.Type]
        REQUEST: _ClassVar[WebSocketMessage.Type]
        RESPONSE: _ClassVar[WebSocketMessage.Type]
    UNKNOWN: WebSocketMessage.Type
    REQUEST: WebSocketMessage.Type
    RESPONSE: WebSocketMessage.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    type: WebSocketMessage.Type
    request: WebSocketRequestMessage
    response: WebSocketResponseMessage
    def __init__(self, type: _Optional[_Union[WebSocketMessage.Type, str]] = ..., request: _Optional[_Union[WebSocketRequestMessage, _Mapping]] = ..., response: _Optional[_Union[WebSocketResponseMessage, _Mapping]] = ...) -> None: ...
