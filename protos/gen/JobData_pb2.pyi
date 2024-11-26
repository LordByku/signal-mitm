import ResumableUploads_pb2 as _ResumableUploads_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CallSyncEventJobRecord(_message.Message):
    __slots__ = ("recipientId", "callId", "direction", "deprecatedEvent", "callEvent")
    class Event(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_ACTION: _ClassVar[CallSyncEventJobRecord.Event]
        ACCEPTED: _ClassVar[CallSyncEventJobRecord.Event]
        NOT_ACCEPTED: _ClassVar[CallSyncEventJobRecord.Event]
        DELETE: _ClassVar[CallSyncEventJobRecord.Event]
        OBSERVED: _ClassVar[CallSyncEventJobRecord.Event]
    UNKNOWN_ACTION: CallSyncEventJobRecord.Event
    ACCEPTED: CallSyncEventJobRecord.Event
    NOT_ACCEPTED: CallSyncEventJobRecord.Event
    DELETE: CallSyncEventJobRecord.Event
    OBSERVED: CallSyncEventJobRecord.Event
    RECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    CALLID_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    DEPRECATEDEVENT_FIELD_NUMBER: _ClassVar[int]
    CALLEVENT_FIELD_NUMBER: _ClassVar[int]
    recipientId: int
    callId: int
    direction: int
    deprecatedEvent: int
    callEvent: CallSyncEventJobRecord.Event
    def __init__(self, recipientId: _Optional[int] = ..., callId: _Optional[int] = ..., direction: _Optional[int] = ..., deprecatedEvent: _Optional[int] = ..., callEvent: _Optional[_Union[CallSyncEventJobRecord.Event, str]] = ...) -> None: ...

class CallSyncEventJobData(_message.Message):
    __slots__ = ("records",)
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[CallSyncEventJobRecord]
    def __init__(self, records: _Optional[_Iterable[_Union[CallSyncEventJobRecord, _Mapping]]] = ...) -> None: ...

class CallLinkRefreshSinceTimestampJobData(_message.Message):
    __slots__ = ("timestamp",)
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    timestamp: int
    def __init__(self, timestamp: _Optional[int] = ...) -> None: ...

class CallLogEventSendJobData(_message.Message):
    __slots__ = ("callLogEvent",)
    CALLLOGEVENT_FIELD_NUMBER: _ClassVar[int]
    callLogEvent: bytes
    def __init__(self, callLogEvent: _Optional[bytes] = ...) -> None: ...

class CallLinkUpdateSendJobData(_message.Message):
    __slots__ = ("callLinkRoomId", "type")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UPDATE: _ClassVar[CallLinkUpdateSendJobData.Type]
    UPDATE: CallLinkUpdateSendJobData.Type
    CALLLINKROOMID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    callLinkRoomId: str
    type: CallLinkUpdateSendJobData.Type
    def __init__(self, callLinkRoomId: _Optional[str] = ..., type: _Optional[_Union[CallLinkUpdateSendJobData.Type, str]] = ...) -> None: ...

class AttachmentUploadJobData(_message.Message):
    __slots__ = ("attachmentId", "uploadSpec")
    ATTACHMENTID_FIELD_NUMBER: _ClassVar[int]
    UPLOADSPEC_FIELD_NUMBER: _ClassVar[int]
    attachmentId: int
    uploadSpec: _ResumableUploads_pb2.ResumableUpload
    def __init__(self, attachmentId: _Optional[int] = ..., uploadSpec: _Optional[_Union[_ResumableUploads_pb2.ResumableUpload, _Mapping]] = ...) -> None: ...

class PreKeysSyncJobData(_message.Message):
    __slots__ = ("forceRefreshRequested",)
    FORCEREFRESHREQUESTED_FIELD_NUMBER: _ClassVar[int]
    forceRefreshRequested: bool
    def __init__(self, forceRefreshRequested: bool = ...) -> None: ...

class ArchiveThumbnailUploadJobData(_message.Message):
    __slots__ = ("attachmentId",)
    ATTACHMENTID_FIELD_NUMBER: _ClassVar[int]
    attachmentId: int
    def __init__(self, attachmentId: _Optional[int] = ...) -> None: ...

class InAppPaymentRedemptionJobData(_message.Message):
    __slots__ = ("inAppPaymentId", "giftMessageId", "makePrimary")
    INAPPPAYMENTID_FIELD_NUMBER: _ClassVar[int]
    GIFTMESSAGEID_FIELD_NUMBER: _ClassVar[int]
    MAKEPRIMARY_FIELD_NUMBER: _ClassVar[int]
    inAppPaymentId: int
    giftMessageId: int
    makePrimary: bool
    def __init__(self, inAppPaymentId: _Optional[int] = ..., giftMessageId: _Optional[int] = ..., makePrimary: bool = ...) -> None: ...

class DeleteSyncJobData(_message.Message):
    __slots__ = ("messageDeletes", "threadDeletes", "localOnlyThreadDeletes", "attachmentDeletes")
    class AddressableMessage(_message.Message):
        __slots__ = ("threadRecipientId", "sentTimestamp", "authorRecipientId")
        THREADRECIPIENTID_FIELD_NUMBER: _ClassVar[int]
        SENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        AUTHORRECIPIENTID_FIELD_NUMBER: _ClassVar[int]
        threadRecipientId: int
        sentTimestamp: int
        authorRecipientId: int
        def __init__(self, threadRecipientId: _Optional[int] = ..., sentTimestamp: _Optional[int] = ..., authorRecipientId: _Optional[int] = ...) -> None: ...
    class AttachmentDelete(_message.Message):
        __slots__ = ("targetMessage", "uuid", "digest", "plaintextHash")
        TARGETMESSAGE_FIELD_NUMBER: _ClassVar[int]
        UUID_FIELD_NUMBER: _ClassVar[int]
        DIGEST_FIELD_NUMBER: _ClassVar[int]
        PLAINTEXTHASH_FIELD_NUMBER: _ClassVar[int]
        targetMessage: DeleteSyncJobData.AddressableMessage
        uuid: bytes
        digest: bytes
        plaintextHash: bytes
        def __init__(self, targetMessage: _Optional[_Union[DeleteSyncJobData.AddressableMessage, _Mapping]] = ..., uuid: _Optional[bytes] = ..., digest: _Optional[bytes] = ..., plaintextHash: _Optional[bytes] = ...) -> None: ...
    class ThreadDelete(_message.Message):
        __slots__ = ("threadRecipientId", "messages", "isFullDelete", "nonExpiringMessages")
        THREADRECIPIENTID_FIELD_NUMBER: _ClassVar[int]
        MESSAGES_FIELD_NUMBER: _ClassVar[int]
        ISFULLDELETE_FIELD_NUMBER: _ClassVar[int]
        NONEXPIRINGMESSAGES_FIELD_NUMBER: _ClassVar[int]
        threadRecipientId: int
        messages: _containers.RepeatedCompositeFieldContainer[DeleteSyncJobData.AddressableMessage]
        isFullDelete: bool
        nonExpiringMessages: _containers.RepeatedCompositeFieldContainer[DeleteSyncJobData.AddressableMessage]
        def __init__(self, threadRecipientId: _Optional[int] = ..., messages: _Optional[_Iterable[_Union[DeleteSyncJobData.AddressableMessage, _Mapping]]] = ..., isFullDelete: bool = ..., nonExpiringMessages: _Optional[_Iterable[_Union[DeleteSyncJobData.AddressableMessage, _Mapping]]] = ...) -> None: ...
    MESSAGEDELETES_FIELD_NUMBER: _ClassVar[int]
    THREADDELETES_FIELD_NUMBER: _ClassVar[int]
    LOCALONLYTHREADDELETES_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTDELETES_FIELD_NUMBER: _ClassVar[int]
    messageDeletes: _containers.RepeatedCompositeFieldContainer[DeleteSyncJobData.AddressableMessage]
    threadDeletes: _containers.RepeatedCompositeFieldContainer[DeleteSyncJobData.ThreadDelete]
    localOnlyThreadDeletes: _containers.RepeatedCompositeFieldContainer[DeleteSyncJobData.ThreadDelete]
    attachmentDeletes: _containers.RepeatedCompositeFieldContainer[DeleteSyncJobData.AttachmentDelete]
    def __init__(self, messageDeletes: _Optional[_Iterable[_Union[DeleteSyncJobData.AddressableMessage, _Mapping]]] = ..., threadDeletes: _Optional[_Iterable[_Union[DeleteSyncJobData.ThreadDelete, _Mapping]]] = ..., localOnlyThreadDeletes: _Optional[_Iterable[_Union[DeleteSyncJobData.ThreadDelete, _Mapping]]] = ..., attachmentDeletes: _Optional[_Iterable[_Union[DeleteSyncJobData.AttachmentDelete, _Mapping]]] = ...) -> None: ...

class Svr3MirrorJobData(_message.Message):
    __slots__ = ("serializedChangeSession",)
    SERIALIZEDCHANGESESSION_FIELD_NUMBER: _ClassVar[int]
    serializedChangeSession: str
    def __init__(self, serializedChangeSession: _Optional[str] = ...) -> None: ...

class GroupCallPeekJobData(_message.Message):
    __slots__ = ("groupRecipientId", "senderRecipientId", "serverTimestamp")
    GROUPRECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    SENDERRECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    SERVERTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    groupRecipientId: int
    senderRecipientId: int
    serverTimestamp: int
    def __init__(self, groupRecipientId: _Optional[int] = ..., senderRecipientId: _Optional[int] = ..., serverTimestamp: _Optional[int] = ...) -> None: ...

class RestoreLocalAttachmentJobData(_message.Message):
    __slots__ = ("attachmentId", "messageId", "fileUri", "fileSize")
    ATTACHMENTID_FIELD_NUMBER: _ClassVar[int]
    MESSAGEID_FIELD_NUMBER: _ClassVar[int]
    FILEURI_FIELD_NUMBER: _ClassVar[int]
    FILESIZE_FIELD_NUMBER: _ClassVar[int]
    attachmentId: int
    messageId: int
    fileUri: str
    fileSize: int
    def __init__(self, attachmentId: _Optional[int] = ..., messageId: _Optional[int] = ..., fileUri: _Optional[str] = ..., fileSize: _Optional[int] = ...) -> None: ...

class BackfillDigestJobData(_message.Message):
    __slots__ = ("attachmentId",)
    ATTACHMENTID_FIELD_NUMBER: _ClassVar[int]
    attachmentId: int
    def __init__(self, attachmentId: _Optional[int] = ...) -> None: ...

class BackfillDigestsForDataFileJobData(_message.Message):
    __slots__ = ("dataFile",)
    DATAFILE_FIELD_NUMBER: _ClassVar[int]
    dataFile: str
    def __init__(self, dataFile: _Optional[str] = ...) -> None: ...

class RestoreAttachmentJobData(_message.Message):
    __slots__ = ("messageId", "attachmentId", "manual")
    MESSAGEID_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTID_FIELD_NUMBER: _ClassVar[int]
    MANUAL_FIELD_NUMBER: _ClassVar[int]
    messageId: int
    attachmentId: int
    manual: bool
    def __init__(self, messageId: _Optional[int] = ..., attachmentId: _Optional[int] = ..., manual: bool = ...) -> None: ...

class CopyAttachmentToArchiveJobData(_message.Message):
    __slots__ = ("attachmentId",)
    ATTACHMENTID_FIELD_NUMBER: _ClassVar[int]
    attachmentId: int
    def __init__(self, attachmentId: _Optional[int] = ...) -> None: ...

class UploadAttachmentToArchiveJobData(_message.Message):
    __slots__ = ("attachmentId", "uploadSpec")
    ATTACHMENTID_FIELD_NUMBER: _ClassVar[int]
    UPLOADSPEC_FIELD_NUMBER: _ClassVar[int]
    attachmentId: int
    uploadSpec: _ResumableUploads_pb2.ResumableUpload
    def __init__(self, attachmentId: _Optional[int] = ..., uploadSpec: _Optional[_Union[_ResumableUploads_pb2.ResumableUpload, _Mapping]] = ...) -> None: ...
