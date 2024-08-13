from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ResumableUpload(_message.Message):
    __slots__ = ("secretKey", "iv", "cdnKey", "cdnNumber", "location", "timeout", "headers")
    class Header(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SECRETKEY_FIELD_NUMBER: _ClassVar[int]
    IV_FIELD_NUMBER: _ClassVar[int]
    CDNKEY_FIELD_NUMBER: _ClassVar[int]
    CDNNUMBER_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    secretKey: bytes
    iv: bytes
    cdnKey: str
    cdnNumber: int
    location: str
    timeout: int
    headers: _containers.RepeatedCompositeFieldContainer[ResumableUpload.Header]
    def __init__(self, secretKey: _Optional[bytes] = ..., iv: _Optional[bytes] = ..., cdnKey: _Optional[str] = ..., cdnNumber: _Optional[int] = ..., location: _Optional[str] = ..., timeout: _Optional[int] = ..., headers: _Optional[_Iterable[_Union[ResumableUpload.Header, _Mapping]]] = ...) -> None: ...
