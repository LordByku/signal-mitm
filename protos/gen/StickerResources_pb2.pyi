from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Pack(_message.Message):
    __slots__ = ("title", "author", "cover", "stickers")
    class Sticker(_message.Message):
        __slots__ = ("id", "emoji", "contentType")
        ID_FIELD_NUMBER: _ClassVar[int]
        EMOJI_FIELD_NUMBER: _ClassVar[int]
        CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
        id: int
        emoji: str
        contentType: str
        def __init__(self, id: _Optional[int] = ..., emoji: _Optional[str] = ..., contentType: _Optional[str] = ...) -> None: ...
    TITLE_FIELD_NUMBER: _ClassVar[int]
    AUTHOR_FIELD_NUMBER: _ClassVar[int]
    COVER_FIELD_NUMBER: _ClassVar[int]
    STICKERS_FIELD_NUMBER: _ClassVar[int]
    title: str
    author: str
    cover: Pack.Sticker
    stickers: _containers.RepeatedCompositeFieldContainer[Pack.Sticker]
    def __init__(self, title: _Optional[str] = ..., author: _Optional[str] = ..., cover: _Optional[_Union[Pack.Sticker, _Mapping]] = ..., stickers: _Optional[_Iterable[_Union[Pack.Sticker, _Mapping]]] = ...) -> None: ...
