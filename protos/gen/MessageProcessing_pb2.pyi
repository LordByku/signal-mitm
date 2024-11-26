from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnvelopeMetadata(_message.Message):
    __slots__ = ("sourceServiceId", "sourceE164", "sourceDeviceId", "sealedSender", "groupId", "destinationServiceId")
    SOURCESERVICEID_FIELD_NUMBER: _ClassVar[int]
    SOURCEE164_FIELD_NUMBER: _ClassVar[int]
    SOURCEDEVICEID_FIELD_NUMBER: _ClassVar[int]
    SEALEDSENDER_FIELD_NUMBER: _ClassVar[int]
    GROUPID_FIELD_NUMBER: _ClassVar[int]
    DESTINATIONSERVICEID_FIELD_NUMBER: _ClassVar[int]
    sourceServiceId: bytes
    sourceE164: str
    sourceDeviceId: int
    sealedSender: bool
    groupId: bytes
    destinationServiceId: bytes
    def __init__(self, sourceServiceId: _Optional[bytes] = ..., sourceE164: _Optional[str] = ..., sourceDeviceId: _Optional[int] = ..., sealedSender: bool = ..., groupId: _Optional[bytes] = ..., destinationServiceId: _Optional[bytes] = ...) -> None: ...

class CompleteMessage(_message.Message):
    __slots__ = ("envelope", "content", "metadata", "serverDeliveredTimestamp")
    ENVELOPE_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SERVERDELIVEREDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    envelope: bytes
    content: bytes
    metadata: EnvelopeMetadata
    serverDeliveredTimestamp: int
    def __init__(self, envelope: _Optional[bytes] = ..., content: _Optional[bytes] = ..., metadata: _Optional[_Union[EnvelopeMetadata, _Mapping]] = ..., serverDeliveredTimestamp: _Optional[int] = ...) -> None: ...
