from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class JumbomojiPack(_message.Message):
    __slots__ = ("items",)
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    items: _containers.RepeatedCompositeFieldContainer[JumbomojiItem]
    def __init__(self, items: _Optional[_Iterable[_Union[JumbomojiItem, _Mapping]]] = ...) -> None: ...

class JumbomojiItem(_message.Message):
    __slots__ = ("name", "image")
    NAME_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    name: str
    image: bytes
    def __init__(self, name: _Optional[str] = ..., image: _Optional[bytes] = ...) -> None: ...
