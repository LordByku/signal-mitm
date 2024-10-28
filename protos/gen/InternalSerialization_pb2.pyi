import SignalService_pb2 as _SignalService_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SignalServiceContentProto(_message.Message):
    __slots__ = ("localAddress", "metadata", "legacyDataMessage", "content")
    LOCALADDRESS_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    LEGACYDATAMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    localAddress: AddressProto
    metadata: MetadataProto
    legacyDataMessage: _SignalService_pb2.DataMessage
    content: _SignalService_pb2.Content
    def __init__(self, localAddress: _Optional[_Union[AddressProto, _Mapping]] = ..., metadata: _Optional[_Union[MetadataProto, _Mapping]] = ..., legacyDataMessage: _Optional[_Union[_SignalService_pb2.DataMessage, _Mapping]] = ..., content: _Optional[_Union[_SignalService_pb2.Content, _Mapping]] = ...) -> None: ...

class SignalServiceEnvelopeProto(_message.Message):
    __slots__ = ("type", "sourceServiceId", "deviceId", "content", "timestamp", "serverReceivedTimestamp", "serverDeliveredTimestamp", "serverGuid", "destinationServiceId", "urgent", "story", "reportingToken")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SOURCESERVICEID_FIELD_NUMBER: _ClassVar[int]
    DEVICEID_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SERVERRECEIVEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SERVERDELIVEREDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SERVERGUID_FIELD_NUMBER: _ClassVar[int]
    DESTINATIONSERVICEID_FIELD_NUMBER: _ClassVar[int]
    URGENT_FIELD_NUMBER: _ClassVar[int]
    STORY_FIELD_NUMBER: _ClassVar[int]
    REPORTINGTOKEN_FIELD_NUMBER: _ClassVar[int]
    type: int
    sourceServiceId: str
    deviceId: int
    content: bytes
    timestamp: int
    serverReceivedTimestamp: int
    serverDeliveredTimestamp: int
    serverGuid: str
    destinationServiceId: str
    urgent: bool
    story: bool
    reportingToken: bytes
    def __init__(self, type: _Optional[int] = ..., sourceServiceId: _Optional[str] = ..., deviceId: _Optional[int] = ..., content: _Optional[bytes] = ..., timestamp: _Optional[int] = ..., serverReceivedTimestamp: _Optional[int] = ..., serverDeliveredTimestamp: _Optional[int] = ..., serverGuid: _Optional[str] = ..., destinationServiceId: _Optional[str] = ..., urgent: bool = ..., story: bool = ..., reportingToken: _Optional[bytes] = ...) -> None: ...

class MetadataProto(_message.Message):
    __slots__ = ("address", "senderDevice", "timestamp", "serverReceivedTimestamp", "serverDeliveredTimestamp", "needsReceipt", "serverGuid", "groupId", "destinationUuid")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SENDERDEVICE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SERVERRECEIVEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SERVERDELIVEREDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    NEEDSRECEIPT_FIELD_NUMBER: _ClassVar[int]
    SERVERGUID_FIELD_NUMBER: _ClassVar[int]
    GROUPID_FIELD_NUMBER: _ClassVar[int]
    DESTINATIONUUID_FIELD_NUMBER: _ClassVar[int]
    address: AddressProto
    senderDevice: int
    timestamp: int
    serverReceivedTimestamp: int
    serverDeliveredTimestamp: int
    needsReceipt: bool
    serverGuid: str
    groupId: bytes
    destinationUuid: str
    def __init__(self, address: _Optional[_Union[AddressProto, _Mapping]] = ..., senderDevice: _Optional[int] = ..., timestamp: _Optional[int] = ..., serverReceivedTimestamp: _Optional[int] = ..., serverDeliveredTimestamp: _Optional[int] = ..., needsReceipt: bool = ..., serverGuid: _Optional[str] = ..., groupId: _Optional[bytes] = ..., destinationUuid: _Optional[str] = ...) -> None: ...

class AddressProto(_message.Message):
    __slots__ = ("uuid", "e164")
    UUID_FIELD_NUMBER: _ClassVar[int]
    E164_FIELD_NUMBER: _ClassVar[int]
    uuid: bytes
    e164: str
    def __init__(self, uuid: _Optional[bytes] = ..., e164: _Optional[str] = ...) -> None: ...
