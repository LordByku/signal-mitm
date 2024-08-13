from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class SvrAuthToken(_message.Message):
    __slots__ = ("svr2Tokens", "svr3Tokens")
    SVR2TOKENS_FIELD_NUMBER: _ClassVar[int]
    SVR3TOKENS_FIELD_NUMBER: _ClassVar[int]
    svr2Tokens: _containers.RepeatedScalarFieldContainer[str]
    svr3Tokens: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, svr2Tokens: _Optional[_Iterable[str]] = ..., svr3Tokens: _Optional[_Iterable[str]] = ...) -> None: ...
