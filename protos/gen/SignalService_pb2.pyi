from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Envelope(_message.Message):
    __slots__ = ("type", "sourceServiceId", "sourceDevice", "destinationServiceId", "timestamp", "content", "serverGuid", "serverTimestamp", "urgent", "story", "reportingToken")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[Envelope.Type]
        CIPHERTEXT: _ClassVar[Envelope.Type]
        KEY_EXCHANGE: _ClassVar[Envelope.Type]
        PREKEY_BUNDLE: _ClassVar[Envelope.Type]
        RECEIPT: _ClassVar[Envelope.Type]
        UNIDENTIFIED_SENDER: _ClassVar[Envelope.Type]
        PLAINTEXT_CONTENT: _ClassVar[Envelope.Type]
    UNKNOWN: Envelope.Type
    CIPHERTEXT: Envelope.Type
    KEY_EXCHANGE: Envelope.Type
    PREKEY_BUNDLE: Envelope.Type
    RECEIPT: Envelope.Type
    UNIDENTIFIED_SENDER: Envelope.Type
    PLAINTEXT_CONTENT: Envelope.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SOURCESERVICEID_FIELD_NUMBER: _ClassVar[int]
    SOURCEDEVICE_FIELD_NUMBER: _ClassVar[int]
    DESTINATIONSERVICEID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    SERVERGUID_FIELD_NUMBER: _ClassVar[int]
    SERVERTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    URGENT_FIELD_NUMBER: _ClassVar[int]
    STORY_FIELD_NUMBER: _ClassVar[int]
    REPORTINGTOKEN_FIELD_NUMBER: _ClassVar[int]
    type: Envelope.Type
    sourceServiceId: str
    sourceDevice: int
    destinationServiceId: str
    timestamp: int
    content: bytes
    serverGuid: str
    serverTimestamp: int
    urgent: bool
    story: bool
    reportingToken: bytes
    def __init__(self, type: _Optional[_Union[Envelope.Type, str]] = ..., sourceServiceId: _Optional[str] = ..., sourceDevice: _Optional[int] = ..., destinationServiceId: _Optional[str] = ..., timestamp: _Optional[int] = ..., content: _Optional[bytes] = ..., serverGuid: _Optional[str] = ..., serverTimestamp: _Optional[int] = ..., urgent: bool = ..., story: bool = ..., reportingToken: _Optional[bytes] = ...) -> None: ...

class Content(_message.Message):
    __slots__ = ("dataMessage", "syncMessage", "callMessage", "nullMessage", "receiptMessage", "typingMessage", "senderKeyDistributionMessage", "decryptionErrorMessage", "storyMessage", "pniSignatureMessage", "editMessage")
    DATAMESSAGE_FIELD_NUMBER: _ClassVar[int]
    SYNCMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CALLMESSAGE_FIELD_NUMBER: _ClassVar[int]
    NULLMESSAGE_FIELD_NUMBER: _ClassVar[int]
    RECEIPTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    TYPINGMESSAGE_FIELD_NUMBER: _ClassVar[int]
    SENDERKEYDISTRIBUTIONMESSAGE_FIELD_NUMBER: _ClassVar[int]
    DECRYPTIONERRORMESSAGE_FIELD_NUMBER: _ClassVar[int]
    STORYMESSAGE_FIELD_NUMBER: _ClassVar[int]
    PNISIGNATUREMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EDITMESSAGE_FIELD_NUMBER: _ClassVar[int]
    dataMessage: DataMessage
    syncMessage: SyncMessage
    callMessage: CallMessage
    nullMessage: NullMessage
    receiptMessage: ReceiptMessage
    typingMessage: TypingMessage
    senderKeyDistributionMessage: bytes
    decryptionErrorMessage: bytes
    storyMessage: StoryMessage
    pniSignatureMessage: PniSignatureMessage
    editMessage: EditMessage
    def __init__(self, dataMessage: _Optional[_Union[DataMessage, _Mapping]] = ..., syncMessage: _Optional[_Union[SyncMessage, _Mapping]] = ..., callMessage: _Optional[_Union[CallMessage, _Mapping]] = ..., nullMessage: _Optional[_Union[NullMessage, _Mapping]] = ..., receiptMessage: _Optional[_Union[ReceiptMessage, _Mapping]] = ..., typingMessage: _Optional[_Union[TypingMessage, _Mapping]] = ..., senderKeyDistributionMessage: _Optional[bytes] = ..., decryptionErrorMessage: _Optional[bytes] = ..., storyMessage: _Optional[_Union[StoryMessage, _Mapping]] = ..., pniSignatureMessage: _Optional[_Union[PniSignatureMessage, _Mapping]] = ..., editMessage: _Optional[_Union[EditMessage, _Mapping]] = ...) -> None: ...

class CallMessage(_message.Message):
    __slots__ = ("offer", "answer", "iceUpdate", "busy", "hangup", "destinationDeviceId", "opaque")
    class Offer(_message.Message):
        __slots__ = ("id", "type", "opaque")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            OFFER_AUDIO_CALL: _ClassVar[CallMessage.Offer.Type]
            OFFER_VIDEO_CALL: _ClassVar[CallMessage.Offer.Type]
        OFFER_AUDIO_CALL: CallMessage.Offer.Type
        OFFER_VIDEO_CALL: CallMessage.Offer.Type
        ID_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        OPAQUE_FIELD_NUMBER: _ClassVar[int]
        id: int
        type: CallMessage.Offer.Type
        opaque: bytes
        def __init__(self, id: _Optional[int] = ..., type: _Optional[_Union[CallMessage.Offer.Type, str]] = ..., opaque: _Optional[bytes] = ...) -> None: ...
    class Answer(_message.Message):
        __slots__ = ("id", "opaque")
        ID_FIELD_NUMBER: _ClassVar[int]
        OPAQUE_FIELD_NUMBER: _ClassVar[int]
        id: int
        opaque: bytes
        def __init__(self, id: _Optional[int] = ..., opaque: _Optional[bytes] = ...) -> None: ...
    class IceUpdate(_message.Message):
        __slots__ = ("id", "opaque")
        ID_FIELD_NUMBER: _ClassVar[int]
        OPAQUE_FIELD_NUMBER: _ClassVar[int]
        id: int
        opaque: bytes
        def __init__(self, id: _Optional[int] = ..., opaque: _Optional[bytes] = ...) -> None: ...
    class Busy(_message.Message):
        __slots__ = ("id",)
        ID_FIELD_NUMBER: _ClassVar[int]
        id: int
        def __init__(self, id: _Optional[int] = ...) -> None: ...
    class Hangup(_message.Message):
        __slots__ = ("id", "type", "deviceId")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            HANGUP_NORMAL: _ClassVar[CallMessage.Hangup.Type]
            HANGUP_ACCEPTED: _ClassVar[CallMessage.Hangup.Type]
            HANGUP_DECLINED: _ClassVar[CallMessage.Hangup.Type]
            HANGUP_BUSY: _ClassVar[CallMessage.Hangup.Type]
            HANGUP_NEED_PERMISSION: _ClassVar[CallMessage.Hangup.Type]
        HANGUP_NORMAL: CallMessage.Hangup.Type
        HANGUP_ACCEPTED: CallMessage.Hangup.Type
        HANGUP_DECLINED: CallMessage.Hangup.Type
        HANGUP_BUSY: CallMessage.Hangup.Type
        HANGUP_NEED_PERMISSION: CallMessage.Hangup.Type
        ID_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        DEVICEID_FIELD_NUMBER: _ClassVar[int]
        id: int
        type: CallMessage.Hangup.Type
        deviceId: int
        def __init__(self, id: _Optional[int] = ..., type: _Optional[_Union[CallMessage.Hangup.Type, str]] = ..., deviceId: _Optional[int] = ...) -> None: ...
    class Opaque(_message.Message):
        __slots__ = ("data", "urgency")
        class Urgency(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            DROPPABLE: _ClassVar[CallMessage.Opaque.Urgency]
            HANDLE_IMMEDIATELY: _ClassVar[CallMessage.Opaque.Urgency]
        DROPPABLE: CallMessage.Opaque.Urgency
        HANDLE_IMMEDIATELY: CallMessage.Opaque.Urgency
        DATA_FIELD_NUMBER: _ClassVar[int]
        URGENCY_FIELD_NUMBER: _ClassVar[int]
        data: bytes
        urgency: CallMessage.Opaque.Urgency
        def __init__(self, data: _Optional[bytes] = ..., urgency: _Optional[_Union[CallMessage.Opaque.Urgency, str]] = ...) -> None: ...
    OFFER_FIELD_NUMBER: _ClassVar[int]
    ANSWER_FIELD_NUMBER: _ClassVar[int]
    ICEUPDATE_FIELD_NUMBER: _ClassVar[int]
    BUSY_FIELD_NUMBER: _ClassVar[int]
    HANGUP_FIELD_NUMBER: _ClassVar[int]
    DESTINATIONDEVICEID_FIELD_NUMBER: _ClassVar[int]
    OPAQUE_FIELD_NUMBER: _ClassVar[int]
    offer: CallMessage.Offer
    answer: CallMessage.Answer
    iceUpdate: _containers.RepeatedCompositeFieldContainer[CallMessage.IceUpdate]
    busy: CallMessage.Busy
    hangup: CallMessage.Hangup
    destinationDeviceId: int
    opaque: CallMessage.Opaque
    def __init__(self, offer: _Optional[_Union[CallMessage.Offer, _Mapping]] = ..., answer: _Optional[_Union[CallMessage.Answer, _Mapping]] = ..., iceUpdate: _Optional[_Iterable[_Union[CallMessage.IceUpdate, _Mapping]]] = ..., busy: _Optional[_Union[CallMessage.Busy, _Mapping]] = ..., hangup: _Optional[_Union[CallMessage.Hangup, _Mapping]] = ..., destinationDeviceId: _Optional[int] = ..., opaque: _Optional[_Union[CallMessage.Opaque, _Mapping]] = ...) -> None: ...

class BodyRange(_message.Message):
    __slots__ = ("start", "length", "mentionAci", "style")
    class Style(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[BodyRange.Style]
        BOLD: _ClassVar[BodyRange.Style]
        ITALIC: _ClassVar[BodyRange.Style]
        SPOILER: _ClassVar[BodyRange.Style]
        STRIKETHROUGH: _ClassVar[BodyRange.Style]
        MONOSPACE: _ClassVar[BodyRange.Style]
    NONE: BodyRange.Style
    BOLD: BodyRange.Style
    ITALIC: BodyRange.Style
    SPOILER: BodyRange.Style
    STRIKETHROUGH: BodyRange.Style
    MONOSPACE: BodyRange.Style
    START_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    MENTIONACI_FIELD_NUMBER: _ClassVar[int]
    STYLE_FIELD_NUMBER: _ClassVar[int]
    start: int
    length: int
    mentionAci: str
    style: BodyRange.Style
    def __init__(self, start: _Optional[int] = ..., length: _Optional[int] = ..., mentionAci: _Optional[str] = ..., style: _Optional[_Union[BodyRange.Style, str]] = ...) -> None: ...

class DataMessage(_message.Message):
    __slots__ = ("body", "attachments", "groupV2", "flags", "expireTimer", "expireTimerVersion", "profileKey", "timestamp", "quote", "contact", "preview", "sticker", "requiredProtocolVersion", "isViewOnce", "reaction", "delete", "bodyRanges", "groupCallUpdate", "payment", "storyContext", "giftBadge")
    class Flags(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        END_SESSION: _ClassVar[DataMessage.Flags]
        EXPIRATION_TIMER_UPDATE: _ClassVar[DataMessage.Flags]
        PROFILE_KEY_UPDATE: _ClassVar[DataMessage.Flags]
    END_SESSION: DataMessage.Flags
    EXPIRATION_TIMER_UPDATE: DataMessage.Flags
    PROFILE_KEY_UPDATE: DataMessage.Flags
    class ProtocolVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        INITIAL: _ClassVar[DataMessage.ProtocolVersion]
        MESSAGE_TIMERS: _ClassVar[DataMessage.ProtocolVersion]
        VIEW_ONCE: _ClassVar[DataMessage.ProtocolVersion]
        VIEW_ONCE_VIDEO: _ClassVar[DataMessage.ProtocolVersion]
        REACTIONS: _ClassVar[DataMessage.ProtocolVersion]
        CDN_SELECTOR_ATTACHMENTS: _ClassVar[DataMessage.ProtocolVersion]
        MENTIONS: _ClassVar[DataMessage.ProtocolVersion]
        PAYMENTS: _ClassVar[DataMessage.ProtocolVersion]
        CURRENT: _ClassVar[DataMessage.ProtocolVersion]
    INITIAL: DataMessage.ProtocolVersion
    MESSAGE_TIMERS: DataMessage.ProtocolVersion
    VIEW_ONCE: DataMessage.ProtocolVersion
    VIEW_ONCE_VIDEO: DataMessage.ProtocolVersion
    REACTIONS: DataMessage.ProtocolVersion
    CDN_SELECTOR_ATTACHMENTS: DataMessage.ProtocolVersion
    MENTIONS: DataMessage.ProtocolVersion
    PAYMENTS: DataMessage.ProtocolVersion
    CURRENT: DataMessage.ProtocolVersion
    class Quote(_message.Message):
        __slots__ = ("id", "authorAci", "text", "attachments", "bodyRanges", "type")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            NORMAL: _ClassVar[DataMessage.Quote.Type]
            GIFT_BADGE: _ClassVar[DataMessage.Quote.Type]
        NORMAL: DataMessage.Quote.Type
        GIFT_BADGE: DataMessage.Quote.Type
        class QuotedAttachment(_message.Message):
            __slots__ = ("contentType", "fileName", "thumbnail")
            CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
            FILENAME_FIELD_NUMBER: _ClassVar[int]
            THUMBNAIL_FIELD_NUMBER: _ClassVar[int]
            contentType: str
            fileName: str
            thumbnail: AttachmentPointer
            def __init__(self, contentType: _Optional[str] = ..., fileName: _Optional[str] = ..., thumbnail: _Optional[_Union[AttachmentPointer, _Mapping]] = ...) -> None: ...
        ID_FIELD_NUMBER: _ClassVar[int]
        AUTHORACI_FIELD_NUMBER: _ClassVar[int]
        TEXT_FIELD_NUMBER: _ClassVar[int]
        ATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
        BODYRANGES_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        id: int
        authorAci: str
        text: str
        attachments: _containers.RepeatedCompositeFieldContainer[DataMessage.Quote.QuotedAttachment]
        bodyRanges: _containers.RepeatedCompositeFieldContainer[BodyRange]
        type: DataMessage.Quote.Type
        def __init__(self, id: _Optional[int] = ..., authorAci: _Optional[str] = ..., text: _Optional[str] = ..., attachments: _Optional[_Iterable[_Union[DataMessage.Quote.QuotedAttachment, _Mapping]]] = ..., bodyRanges: _Optional[_Iterable[_Union[BodyRange, _Mapping]]] = ..., type: _Optional[_Union[DataMessage.Quote.Type, str]] = ...) -> None: ...
    class Contact(_message.Message):
        __slots__ = ("name", "number", "email", "address", "avatar", "organization")
        class Name(_message.Message):
            __slots__ = ("givenName", "familyName", "prefix", "suffix", "middleName", "nickname")
            GIVENNAME_FIELD_NUMBER: _ClassVar[int]
            FAMILYNAME_FIELD_NUMBER: _ClassVar[int]
            PREFIX_FIELD_NUMBER: _ClassVar[int]
            SUFFIX_FIELD_NUMBER: _ClassVar[int]
            MIDDLENAME_FIELD_NUMBER: _ClassVar[int]
            NICKNAME_FIELD_NUMBER: _ClassVar[int]
            givenName: str
            familyName: str
            prefix: str
            suffix: str
            middleName: str
            nickname: str
            def __init__(self, givenName: _Optional[str] = ..., familyName: _Optional[str] = ..., prefix: _Optional[str] = ..., suffix: _Optional[str] = ..., middleName: _Optional[str] = ..., nickname: _Optional[str] = ...) -> None: ...
        class Phone(_message.Message):
            __slots__ = ("value", "type", "label")
            class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                HOME: _ClassVar[DataMessage.Contact.Phone.Type]
                MOBILE: _ClassVar[DataMessage.Contact.Phone.Type]
                WORK: _ClassVar[DataMessage.Contact.Phone.Type]
                CUSTOM: _ClassVar[DataMessage.Contact.Phone.Type]
            HOME: DataMessage.Contact.Phone.Type
            MOBILE: DataMessage.Contact.Phone.Type
            WORK: DataMessage.Contact.Phone.Type
            CUSTOM: DataMessage.Contact.Phone.Type
            VALUE_FIELD_NUMBER: _ClassVar[int]
            TYPE_FIELD_NUMBER: _ClassVar[int]
            LABEL_FIELD_NUMBER: _ClassVar[int]
            value: str
            type: DataMessage.Contact.Phone.Type
            label: str
            def __init__(self, value: _Optional[str] = ..., type: _Optional[_Union[DataMessage.Contact.Phone.Type, str]] = ..., label: _Optional[str] = ...) -> None: ...
        class Email(_message.Message):
            __slots__ = ("value", "type", "label")
            class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                HOME: _ClassVar[DataMessage.Contact.Email.Type]
                MOBILE: _ClassVar[DataMessage.Contact.Email.Type]
                WORK: _ClassVar[DataMessage.Contact.Email.Type]
                CUSTOM: _ClassVar[DataMessage.Contact.Email.Type]
            HOME: DataMessage.Contact.Email.Type
            MOBILE: DataMessage.Contact.Email.Type
            WORK: DataMessage.Contact.Email.Type
            CUSTOM: DataMessage.Contact.Email.Type
            VALUE_FIELD_NUMBER: _ClassVar[int]
            TYPE_FIELD_NUMBER: _ClassVar[int]
            LABEL_FIELD_NUMBER: _ClassVar[int]
            value: str
            type: DataMessage.Contact.Email.Type
            label: str
            def __init__(self, value: _Optional[str] = ..., type: _Optional[_Union[DataMessage.Contact.Email.Type, str]] = ..., label: _Optional[str] = ...) -> None: ...
        class PostalAddress(_message.Message):
            __slots__ = ("type", "label", "street", "pobox", "neighborhood", "city", "region", "postcode", "country")
            class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                HOME: _ClassVar[DataMessage.Contact.PostalAddress.Type]
                WORK: _ClassVar[DataMessage.Contact.PostalAddress.Type]
                CUSTOM: _ClassVar[DataMessage.Contact.PostalAddress.Type]
            HOME: DataMessage.Contact.PostalAddress.Type
            WORK: DataMessage.Contact.PostalAddress.Type
            CUSTOM: DataMessage.Contact.PostalAddress.Type
            TYPE_FIELD_NUMBER: _ClassVar[int]
            LABEL_FIELD_NUMBER: _ClassVar[int]
            STREET_FIELD_NUMBER: _ClassVar[int]
            POBOX_FIELD_NUMBER: _ClassVar[int]
            NEIGHBORHOOD_FIELD_NUMBER: _ClassVar[int]
            CITY_FIELD_NUMBER: _ClassVar[int]
            REGION_FIELD_NUMBER: _ClassVar[int]
            POSTCODE_FIELD_NUMBER: _ClassVar[int]
            COUNTRY_FIELD_NUMBER: _ClassVar[int]
            type: DataMessage.Contact.PostalAddress.Type
            label: str
            street: str
            pobox: str
            neighborhood: str
            city: str
            region: str
            postcode: str
            country: str
            def __init__(self, type: _Optional[_Union[DataMessage.Contact.PostalAddress.Type, str]] = ..., label: _Optional[str] = ..., street: _Optional[str] = ..., pobox: _Optional[str] = ..., neighborhood: _Optional[str] = ..., city: _Optional[str] = ..., region: _Optional[str] = ..., postcode: _Optional[str] = ..., country: _Optional[str] = ...) -> None: ...
        class Avatar(_message.Message):
            __slots__ = ("avatar", "isProfile")
            AVATAR_FIELD_NUMBER: _ClassVar[int]
            ISPROFILE_FIELD_NUMBER: _ClassVar[int]
            avatar: AttachmentPointer
            isProfile: bool
            def __init__(self, avatar: _Optional[_Union[AttachmentPointer, _Mapping]] = ..., isProfile: bool = ...) -> None: ...
        NAME_FIELD_NUMBER: _ClassVar[int]
        NUMBER_FIELD_NUMBER: _ClassVar[int]
        EMAIL_FIELD_NUMBER: _ClassVar[int]
        ADDRESS_FIELD_NUMBER: _ClassVar[int]
        AVATAR_FIELD_NUMBER: _ClassVar[int]
        ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
        name: DataMessage.Contact.Name
        number: _containers.RepeatedCompositeFieldContainer[DataMessage.Contact.Phone]
        email: _containers.RepeatedCompositeFieldContainer[DataMessage.Contact.Email]
        address: _containers.RepeatedCompositeFieldContainer[DataMessage.Contact.PostalAddress]
        avatar: DataMessage.Contact.Avatar
        organization: str
        def __init__(self, name: _Optional[_Union[DataMessage.Contact.Name, _Mapping]] = ..., number: _Optional[_Iterable[_Union[DataMessage.Contact.Phone, _Mapping]]] = ..., email: _Optional[_Iterable[_Union[DataMessage.Contact.Email, _Mapping]]] = ..., address: _Optional[_Iterable[_Union[DataMessage.Contact.PostalAddress, _Mapping]]] = ..., avatar: _Optional[_Union[DataMessage.Contact.Avatar, _Mapping]] = ..., organization: _Optional[str] = ...) -> None: ...
    class Sticker(_message.Message):
        __slots__ = ("packId", "packKey", "stickerId", "data", "emoji")
        PACKID_FIELD_NUMBER: _ClassVar[int]
        PACKKEY_FIELD_NUMBER: _ClassVar[int]
        STICKERID_FIELD_NUMBER: _ClassVar[int]
        DATA_FIELD_NUMBER: _ClassVar[int]
        EMOJI_FIELD_NUMBER: _ClassVar[int]
        packId: bytes
        packKey: bytes
        stickerId: int
        data: AttachmentPointer
        emoji: str
        def __init__(self, packId: _Optional[bytes] = ..., packKey: _Optional[bytes] = ..., stickerId: _Optional[int] = ..., data: _Optional[_Union[AttachmentPointer, _Mapping]] = ..., emoji: _Optional[str] = ...) -> None: ...
    class Reaction(_message.Message):
        __slots__ = ("emoji", "remove", "targetAuthorAci", "targetSentTimestamp")
        EMOJI_FIELD_NUMBER: _ClassVar[int]
        REMOVE_FIELD_NUMBER: _ClassVar[int]
        TARGETAUTHORACI_FIELD_NUMBER: _ClassVar[int]
        TARGETSENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        emoji: str
        remove: bool
        targetAuthorAci: str
        targetSentTimestamp: int
        def __init__(self, emoji: _Optional[str] = ..., remove: bool = ..., targetAuthorAci: _Optional[str] = ..., targetSentTimestamp: _Optional[int] = ...) -> None: ...
    class Delete(_message.Message):
        __slots__ = ("targetSentTimestamp",)
        TARGETSENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        targetSentTimestamp: int
        def __init__(self, targetSentTimestamp: _Optional[int] = ...) -> None: ...
    class GroupCallUpdate(_message.Message):
        __slots__ = ("eraId",)
        ERAID_FIELD_NUMBER: _ClassVar[int]
        eraId: str
        def __init__(self, eraId: _Optional[str] = ...) -> None: ...
    class StoryContext(_message.Message):
        __slots__ = ("authorAci", "sentTimestamp")
        AUTHORACI_FIELD_NUMBER: _ClassVar[int]
        SENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        authorAci: str
        sentTimestamp: int
        def __init__(self, authorAci: _Optional[str] = ..., sentTimestamp: _Optional[int] = ...) -> None: ...
    class Payment(_message.Message):
        __slots__ = ("notification", "activation")
        class Amount(_message.Message):
            __slots__ = ("mobileCoin",)
            class MobileCoin(_message.Message):
                __slots__ = ("picoMob",)
                PICOMOB_FIELD_NUMBER: _ClassVar[int]
                picoMob: int
                def __init__(self, picoMob: _Optional[int] = ...) -> None: ...
            MOBILECOIN_FIELD_NUMBER: _ClassVar[int]
            mobileCoin: DataMessage.Payment.Amount.MobileCoin
            def __init__(self, mobileCoin: _Optional[_Union[DataMessage.Payment.Amount.MobileCoin, _Mapping]] = ...) -> None: ...
        class Notification(_message.Message):
            __slots__ = ("mobileCoin", "note")
            class MobileCoin(_message.Message):
                __slots__ = ("receipt",)
                RECEIPT_FIELD_NUMBER: _ClassVar[int]
                receipt: bytes
                def __init__(self, receipt: _Optional[bytes] = ...) -> None: ...
            MOBILECOIN_FIELD_NUMBER: _ClassVar[int]
            NOTE_FIELD_NUMBER: _ClassVar[int]
            mobileCoin: DataMessage.Payment.Notification.MobileCoin
            note: str
            def __init__(self, mobileCoin: _Optional[_Union[DataMessage.Payment.Notification.MobileCoin, _Mapping]] = ..., note: _Optional[str] = ...) -> None: ...
        class Activation(_message.Message):
            __slots__ = ("type",)
            class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                REQUEST: _ClassVar[DataMessage.Payment.Activation.Type]
                ACTIVATED: _ClassVar[DataMessage.Payment.Activation.Type]
            REQUEST: DataMessage.Payment.Activation.Type
            ACTIVATED: DataMessage.Payment.Activation.Type
            TYPE_FIELD_NUMBER: _ClassVar[int]
            type: DataMessage.Payment.Activation.Type
            def __init__(self, type: _Optional[_Union[DataMessage.Payment.Activation.Type, str]] = ...) -> None: ...
        NOTIFICATION_FIELD_NUMBER: _ClassVar[int]
        ACTIVATION_FIELD_NUMBER: _ClassVar[int]
        notification: DataMessage.Payment.Notification
        activation: DataMessage.Payment.Activation
        def __init__(self, notification: _Optional[_Union[DataMessage.Payment.Notification, _Mapping]] = ..., activation: _Optional[_Union[DataMessage.Payment.Activation, _Mapping]] = ...) -> None: ...
    class GiftBadge(_message.Message):
        __slots__ = ("receiptCredentialPresentation",)
        RECEIPTCREDENTIALPRESENTATION_FIELD_NUMBER: _ClassVar[int]
        receiptCredentialPresentation: bytes
        def __init__(self, receiptCredentialPresentation: _Optional[bytes] = ...) -> None: ...
    BODY_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    GROUPV2_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    EXPIRETIMER_FIELD_NUMBER: _ClassVar[int]
    EXPIRETIMERVERSION_FIELD_NUMBER: _ClassVar[int]
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    QUOTE_FIELD_NUMBER: _ClassVar[int]
    CONTACT_FIELD_NUMBER: _ClassVar[int]
    PREVIEW_FIELD_NUMBER: _ClassVar[int]
    STICKER_FIELD_NUMBER: _ClassVar[int]
    REQUIREDPROTOCOLVERSION_FIELD_NUMBER: _ClassVar[int]
    ISVIEWONCE_FIELD_NUMBER: _ClassVar[int]
    REACTION_FIELD_NUMBER: _ClassVar[int]
    DELETE_FIELD_NUMBER: _ClassVar[int]
    BODYRANGES_FIELD_NUMBER: _ClassVar[int]
    GROUPCALLUPDATE_FIELD_NUMBER: _ClassVar[int]
    PAYMENT_FIELD_NUMBER: _ClassVar[int]
    STORYCONTEXT_FIELD_NUMBER: _ClassVar[int]
    GIFTBADGE_FIELD_NUMBER: _ClassVar[int]
    body: str
    attachments: _containers.RepeatedCompositeFieldContainer[AttachmentPointer]
    groupV2: GroupContextV2
    flags: int
    expireTimer: int
    expireTimerVersion: int
    profileKey: bytes
    timestamp: int
    quote: DataMessage.Quote
    contact: _containers.RepeatedCompositeFieldContainer[DataMessage.Contact]
    preview: _containers.RepeatedCompositeFieldContainer[Preview]
    sticker: DataMessage.Sticker
    requiredProtocolVersion: int
    isViewOnce: bool
    reaction: DataMessage.Reaction
    delete: DataMessage.Delete
    bodyRanges: _containers.RepeatedCompositeFieldContainer[BodyRange]
    groupCallUpdate: DataMessage.GroupCallUpdate
    payment: DataMessage.Payment
    storyContext: DataMessage.StoryContext
    giftBadge: DataMessage.GiftBadge
    def __init__(self, body: _Optional[str] = ..., attachments: _Optional[_Iterable[_Union[AttachmentPointer, _Mapping]]] = ..., groupV2: _Optional[_Union[GroupContextV2, _Mapping]] = ..., flags: _Optional[int] = ..., expireTimer: _Optional[int] = ..., expireTimerVersion: _Optional[int] = ..., profileKey: _Optional[bytes] = ..., timestamp: _Optional[int] = ..., quote: _Optional[_Union[DataMessage.Quote, _Mapping]] = ..., contact: _Optional[_Iterable[_Union[DataMessage.Contact, _Mapping]]] = ..., preview: _Optional[_Iterable[_Union[Preview, _Mapping]]] = ..., sticker: _Optional[_Union[DataMessage.Sticker, _Mapping]] = ..., requiredProtocolVersion: _Optional[int] = ..., isViewOnce: bool = ..., reaction: _Optional[_Union[DataMessage.Reaction, _Mapping]] = ..., delete: _Optional[_Union[DataMessage.Delete, _Mapping]] = ..., bodyRanges: _Optional[_Iterable[_Union[BodyRange, _Mapping]]] = ..., groupCallUpdate: _Optional[_Union[DataMessage.GroupCallUpdate, _Mapping]] = ..., payment: _Optional[_Union[DataMessage.Payment, _Mapping]] = ..., storyContext: _Optional[_Union[DataMessage.StoryContext, _Mapping]] = ..., giftBadge: _Optional[_Union[DataMessage.GiftBadge, _Mapping]] = ...) -> None: ...

class NullMessage(_message.Message):
    __slots__ = ("padding",)
    PADDING_FIELD_NUMBER: _ClassVar[int]
    padding: bytes
    def __init__(self, padding: _Optional[bytes] = ...) -> None: ...

class ReceiptMessage(_message.Message):
    __slots__ = ("type", "timestamp")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DELIVERY: _ClassVar[ReceiptMessage.Type]
        READ: _ClassVar[ReceiptMessage.Type]
        VIEWED: _ClassVar[ReceiptMessage.Type]
    DELIVERY: ReceiptMessage.Type
    READ: ReceiptMessage.Type
    VIEWED: ReceiptMessage.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    type: ReceiptMessage.Type
    timestamp: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, type: _Optional[_Union[ReceiptMessage.Type, str]] = ..., timestamp: _Optional[_Iterable[int]] = ...) -> None: ...

class TypingMessage(_message.Message):
    __slots__ = ("timestamp", "action", "groupId")
    class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        STARTED: _ClassVar[TypingMessage.Action]
        STOPPED: _ClassVar[TypingMessage.Action]
    STARTED: TypingMessage.Action
    STOPPED: TypingMessage.Action
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    GROUPID_FIELD_NUMBER: _ClassVar[int]
    timestamp: int
    action: TypingMessage.Action
    groupId: bytes
    def __init__(self, timestamp: _Optional[int] = ..., action: _Optional[_Union[TypingMessage.Action, str]] = ..., groupId: _Optional[bytes] = ...) -> None: ...

class StoryMessage(_message.Message):
    __slots__ = ("profileKey", "group", "fileAttachment", "textAttachment", "allowsReplies", "bodyRanges")
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    FILEATTACHMENT_FIELD_NUMBER: _ClassVar[int]
    TEXTATTACHMENT_FIELD_NUMBER: _ClassVar[int]
    ALLOWSREPLIES_FIELD_NUMBER: _ClassVar[int]
    BODYRANGES_FIELD_NUMBER: _ClassVar[int]
    profileKey: bytes
    group: GroupContextV2
    fileAttachment: AttachmentPointer
    textAttachment: TextAttachment
    allowsReplies: bool
    bodyRanges: _containers.RepeatedCompositeFieldContainer[BodyRange]
    def __init__(self, profileKey: _Optional[bytes] = ..., group: _Optional[_Union[GroupContextV2, _Mapping]] = ..., fileAttachment: _Optional[_Union[AttachmentPointer, _Mapping]] = ..., textAttachment: _Optional[_Union[TextAttachment, _Mapping]] = ..., allowsReplies: bool = ..., bodyRanges: _Optional[_Iterable[_Union[BodyRange, _Mapping]]] = ...) -> None: ...

class Preview(_message.Message):
    __slots__ = ("url", "title", "image", "description", "date")
    URL_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DATE_FIELD_NUMBER: _ClassVar[int]
    url: str
    title: str
    image: AttachmentPointer
    description: str
    date: int
    def __init__(self, url: _Optional[str] = ..., title: _Optional[str] = ..., image: _Optional[_Union[AttachmentPointer, _Mapping]] = ..., description: _Optional[str] = ..., date: _Optional[int] = ...) -> None: ...

class TextAttachment(_message.Message):
    __slots__ = ("text", "textStyle", "textForegroundColor", "textBackgroundColor", "preview", "gradient", "color")
    class Style(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DEFAULT: _ClassVar[TextAttachment.Style]
        REGULAR: _ClassVar[TextAttachment.Style]
        BOLD: _ClassVar[TextAttachment.Style]
        SERIF: _ClassVar[TextAttachment.Style]
        SCRIPT: _ClassVar[TextAttachment.Style]
        CONDENSED: _ClassVar[TextAttachment.Style]
    DEFAULT: TextAttachment.Style
    REGULAR: TextAttachment.Style
    BOLD: TextAttachment.Style
    SERIF: TextAttachment.Style
    SCRIPT: TextAttachment.Style
    CONDENSED: TextAttachment.Style
    class Gradient(_message.Message):
        __slots__ = ("startColor", "endColor", "angle", "colors", "positions")
        STARTCOLOR_FIELD_NUMBER: _ClassVar[int]
        ENDCOLOR_FIELD_NUMBER: _ClassVar[int]
        ANGLE_FIELD_NUMBER: _ClassVar[int]
        COLORS_FIELD_NUMBER: _ClassVar[int]
        POSITIONS_FIELD_NUMBER: _ClassVar[int]
        startColor: int
        endColor: int
        angle: int
        colors: _containers.RepeatedScalarFieldContainer[int]
        positions: _containers.RepeatedScalarFieldContainer[float]
        def __init__(self, startColor: _Optional[int] = ..., endColor: _Optional[int] = ..., angle: _Optional[int] = ..., colors: _Optional[_Iterable[int]] = ..., positions: _Optional[_Iterable[float]] = ...) -> None: ...
    TEXT_FIELD_NUMBER: _ClassVar[int]
    TEXTSTYLE_FIELD_NUMBER: _ClassVar[int]
    TEXTFOREGROUNDCOLOR_FIELD_NUMBER: _ClassVar[int]
    TEXTBACKGROUNDCOLOR_FIELD_NUMBER: _ClassVar[int]
    PREVIEW_FIELD_NUMBER: _ClassVar[int]
    GRADIENT_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    text: str
    textStyle: TextAttachment.Style
    textForegroundColor: int
    textBackgroundColor: int
    preview: Preview
    gradient: TextAttachment.Gradient
    color: int
    def __init__(self, text: _Optional[str] = ..., textStyle: _Optional[_Union[TextAttachment.Style, str]] = ..., textForegroundColor: _Optional[int] = ..., textBackgroundColor: _Optional[int] = ..., preview: _Optional[_Union[Preview, _Mapping]] = ..., gradient: _Optional[_Union[TextAttachment.Gradient, _Mapping]] = ..., color: _Optional[int] = ...) -> None: ...

class Verified(_message.Message):
    __slots__ = ("destinationAci", "identityKey", "state", "nullMessage")
    class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DEFAULT: _ClassVar[Verified.State]
        VERIFIED: _ClassVar[Verified.State]
        UNVERIFIED: _ClassVar[Verified.State]
    DEFAULT: Verified.State
    VERIFIED: Verified.State
    UNVERIFIED: Verified.State
    DESTINATIONACI_FIELD_NUMBER: _ClassVar[int]
    IDENTITYKEY_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    NULLMESSAGE_FIELD_NUMBER: _ClassVar[int]
    destinationAci: str
    identityKey: bytes
    state: Verified.State
    nullMessage: bytes
    def __init__(self, destinationAci: _Optional[str] = ..., identityKey: _Optional[bytes] = ..., state: _Optional[_Union[Verified.State, str]] = ..., nullMessage: _Optional[bytes] = ...) -> None: ...

class SyncMessage(_message.Message):
    __slots__ = ("sent", "contacts", "request", "read", "blocked", "verified", "configuration", "padding", "stickerPackOperation", "viewOnceOpen", "fetchLatest", "keys", "messageRequestResponse", "outgoingPayment", "viewed", "pniChangeNumber", "callEvent", "callLinkUpdate", "callLogEvent", "deleteForMe")
    class Sent(_message.Message):
        __slots__ = ("destinationE164", "destinationServiceId", "timestamp", "message", "expirationStartTimestamp", "unidentifiedStatus", "isRecipientUpdate", "storyMessage", "storyMessageRecipients", "editMessage")
        class UnidentifiedDeliveryStatus(_message.Message):
            __slots__ = ("destinationServiceId", "unidentified", "destinationIdentityKey")
            DESTINATIONSERVICEID_FIELD_NUMBER: _ClassVar[int]
            UNIDENTIFIED_FIELD_NUMBER: _ClassVar[int]
            DESTINATIONIDENTITYKEY_FIELD_NUMBER: _ClassVar[int]
            destinationServiceId: str
            unidentified: bool
            destinationIdentityKey: bytes
            def __init__(self, destinationServiceId: _Optional[str] = ..., unidentified: bool = ..., destinationIdentityKey: _Optional[bytes] = ...) -> None: ...
        class StoryMessageRecipient(_message.Message):
            __slots__ = ("destinationServiceId", "distributionListIds", "isAllowedToReply")
            DESTINATIONSERVICEID_FIELD_NUMBER: _ClassVar[int]
            DISTRIBUTIONLISTIDS_FIELD_NUMBER: _ClassVar[int]
            ISALLOWEDTOREPLY_FIELD_NUMBER: _ClassVar[int]
            destinationServiceId: str
            distributionListIds: _containers.RepeatedScalarFieldContainer[str]
            isAllowedToReply: bool
            def __init__(self, destinationServiceId: _Optional[str] = ..., distributionListIds: _Optional[_Iterable[str]] = ..., isAllowedToReply: bool = ...) -> None: ...
        DESTINATIONE164_FIELD_NUMBER: _ClassVar[int]
        DESTINATIONSERVICEID_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        MESSAGE_FIELD_NUMBER: _ClassVar[int]
        EXPIRATIONSTARTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        UNIDENTIFIEDSTATUS_FIELD_NUMBER: _ClassVar[int]
        ISRECIPIENTUPDATE_FIELD_NUMBER: _ClassVar[int]
        STORYMESSAGE_FIELD_NUMBER: _ClassVar[int]
        STORYMESSAGERECIPIENTS_FIELD_NUMBER: _ClassVar[int]
        EDITMESSAGE_FIELD_NUMBER: _ClassVar[int]
        destinationE164: str
        destinationServiceId: str
        timestamp: int
        message: DataMessage
        expirationStartTimestamp: int
        unidentifiedStatus: _containers.RepeatedCompositeFieldContainer[SyncMessage.Sent.UnidentifiedDeliveryStatus]
        isRecipientUpdate: bool
        storyMessage: StoryMessage
        storyMessageRecipients: _containers.RepeatedCompositeFieldContainer[SyncMessage.Sent.StoryMessageRecipient]
        editMessage: EditMessage
        def __init__(self, destinationE164: _Optional[str] = ..., destinationServiceId: _Optional[str] = ..., timestamp: _Optional[int] = ..., message: _Optional[_Union[DataMessage, _Mapping]] = ..., expirationStartTimestamp: _Optional[int] = ..., unidentifiedStatus: _Optional[_Iterable[_Union[SyncMessage.Sent.UnidentifiedDeliveryStatus, _Mapping]]] = ..., isRecipientUpdate: bool = ..., storyMessage: _Optional[_Union[StoryMessage, _Mapping]] = ..., storyMessageRecipients: _Optional[_Iterable[_Union[SyncMessage.Sent.StoryMessageRecipient, _Mapping]]] = ..., editMessage: _Optional[_Union[EditMessage, _Mapping]] = ...) -> None: ...
    class Contacts(_message.Message):
        __slots__ = ("blob", "complete")
        BLOB_FIELD_NUMBER: _ClassVar[int]
        COMPLETE_FIELD_NUMBER: _ClassVar[int]
        blob: AttachmentPointer
        complete: bool
        def __init__(self, blob: _Optional[_Union[AttachmentPointer, _Mapping]] = ..., complete: bool = ...) -> None: ...
    class Blocked(_message.Message):
        __slots__ = ("numbers", "acis", "groupIds")
        NUMBERS_FIELD_NUMBER: _ClassVar[int]
        ACIS_FIELD_NUMBER: _ClassVar[int]
        GROUPIDS_FIELD_NUMBER: _ClassVar[int]
        numbers: _containers.RepeatedScalarFieldContainer[str]
        acis: _containers.RepeatedScalarFieldContainer[str]
        groupIds: _containers.RepeatedScalarFieldContainer[bytes]
        def __init__(self, numbers: _Optional[_Iterable[str]] = ..., acis: _Optional[_Iterable[str]] = ..., groupIds: _Optional[_Iterable[bytes]] = ...) -> None: ...
    class Request(_message.Message):
        __slots__ = ("type",)
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[SyncMessage.Request.Type]
            CONTACTS: _ClassVar[SyncMessage.Request.Type]
            BLOCKED: _ClassVar[SyncMessage.Request.Type]
            CONFIGURATION: _ClassVar[SyncMessage.Request.Type]
            KEYS: _ClassVar[SyncMessage.Request.Type]
            PNI_IDENTITY: _ClassVar[SyncMessage.Request.Type]
        UNKNOWN: SyncMessage.Request.Type
        CONTACTS: SyncMessage.Request.Type
        BLOCKED: SyncMessage.Request.Type
        CONFIGURATION: SyncMessage.Request.Type
        KEYS: SyncMessage.Request.Type
        PNI_IDENTITY: SyncMessage.Request.Type
        TYPE_FIELD_NUMBER: _ClassVar[int]
        type: SyncMessage.Request.Type
        def __init__(self, type: _Optional[_Union[SyncMessage.Request.Type, str]] = ...) -> None: ...
    class Read(_message.Message):
        __slots__ = ("senderAci", "timestamp")
        SENDERACI_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        senderAci: str
        timestamp: int
        def __init__(self, senderAci: _Optional[str] = ..., timestamp: _Optional[int] = ...) -> None: ...
    class Viewed(_message.Message):
        __slots__ = ("senderAci", "timestamp")
        SENDERACI_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        senderAci: str
        timestamp: int
        def __init__(self, senderAci: _Optional[str] = ..., timestamp: _Optional[int] = ...) -> None: ...
    class Configuration(_message.Message):
        __slots__ = ("readReceipts", "unidentifiedDeliveryIndicators", "typingIndicators", "provisioningVersion", "linkPreviews")
        READRECEIPTS_FIELD_NUMBER: _ClassVar[int]
        UNIDENTIFIEDDELIVERYINDICATORS_FIELD_NUMBER: _ClassVar[int]
        TYPINGINDICATORS_FIELD_NUMBER: _ClassVar[int]
        PROVISIONINGVERSION_FIELD_NUMBER: _ClassVar[int]
        LINKPREVIEWS_FIELD_NUMBER: _ClassVar[int]
        readReceipts: bool
        unidentifiedDeliveryIndicators: bool
        typingIndicators: bool
        provisioningVersion: int
        linkPreviews: bool
        def __init__(self, readReceipts: bool = ..., unidentifiedDeliveryIndicators: bool = ..., typingIndicators: bool = ..., provisioningVersion: _Optional[int] = ..., linkPreviews: bool = ...) -> None: ...
    class StickerPackOperation(_message.Message):
        __slots__ = ("packId", "packKey", "type")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            INSTALL: _ClassVar[SyncMessage.StickerPackOperation.Type]
            REMOVE: _ClassVar[SyncMessage.StickerPackOperation.Type]
        INSTALL: SyncMessage.StickerPackOperation.Type
        REMOVE: SyncMessage.StickerPackOperation.Type
        PACKID_FIELD_NUMBER: _ClassVar[int]
        PACKKEY_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        packId: bytes
        packKey: bytes
        type: SyncMessage.StickerPackOperation.Type
        def __init__(self, packId: _Optional[bytes] = ..., packKey: _Optional[bytes] = ..., type: _Optional[_Union[SyncMessage.StickerPackOperation.Type, str]] = ...) -> None: ...
    class ViewOnceOpen(_message.Message):
        __slots__ = ("senderAci", "timestamp")
        SENDERACI_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        senderAci: str
        timestamp: int
        def __init__(self, senderAci: _Optional[str] = ..., timestamp: _Optional[int] = ...) -> None: ...
    class FetchLatest(_message.Message):
        __slots__ = ("type",)
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[SyncMessage.FetchLatest.Type]
            LOCAL_PROFILE: _ClassVar[SyncMessage.FetchLatest.Type]
            STORAGE_MANIFEST: _ClassVar[SyncMessage.FetchLatest.Type]
            SUBSCRIPTION_STATUS: _ClassVar[SyncMessage.FetchLatest.Type]
        UNKNOWN: SyncMessage.FetchLatest.Type
        LOCAL_PROFILE: SyncMessage.FetchLatest.Type
        STORAGE_MANIFEST: SyncMessage.FetchLatest.Type
        SUBSCRIPTION_STATUS: SyncMessage.FetchLatest.Type
        TYPE_FIELD_NUMBER: _ClassVar[int]
        type: SyncMessage.FetchLatest.Type
        def __init__(self, type: _Optional[_Union[SyncMessage.FetchLatest.Type, str]] = ...) -> None: ...
    class Keys(_message.Message):
        __slots__ = ("storageService", "master")
        STORAGESERVICE_FIELD_NUMBER: _ClassVar[int]
        MASTER_FIELD_NUMBER: _ClassVar[int]
        storageService: bytes
        master: bytes
        def __init__(self, storageService: _Optional[bytes] = ..., master: _Optional[bytes] = ...) -> None: ...
    class MessageRequestResponse(_message.Message):
        __slots__ = ("threadAci", "groupId", "type")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[SyncMessage.MessageRequestResponse.Type]
            ACCEPT: _ClassVar[SyncMessage.MessageRequestResponse.Type]
            DELETE: _ClassVar[SyncMessage.MessageRequestResponse.Type]
            BLOCK: _ClassVar[SyncMessage.MessageRequestResponse.Type]
            BLOCK_AND_DELETE: _ClassVar[SyncMessage.MessageRequestResponse.Type]
            SPAM: _ClassVar[SyncMessage.MessageRequestResponse.Type]
            BLOCK_AND_SPAM: _ClassVar[SyncMessage.MessageRequestResponse.Type]
        UNKNOWN: SyncMessage.MessageRequestResponse.Type
        ACCEPT: SyncMessage.MessageRequestResponse.Type
        DELETE: SyncMessage.MessageRequestResponse.Type
        BLOCK: SyncMessage.MessageRequestResponse.Type
        BLOCK_AND_DELETE: SyncMessage.MessageRequestResponse.Type
        SPAM: SyncMessage.MessageRequestResponse.Type
        BLOCK_AND_SPAM: SyncMessage.MessageRequestResponse.Type
        THREADACI_FIELD_NUMBER: _ClassVar[int]
        GROUPID_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        threadAci: str
        groupId: bytes
        type: SyncMessage.MessageRequestResponse.Type
        def __init__(self, threadAci: _Optional[str] = ..., groupId: _Optional[bytes] = ..., type: _Optional[_Union[SyncMessage.MessageRequestResponse.Type, str]] = ...) -> None: ...
    class OutgoingPayment(_message.Message):
        __slots__ = ("recipientServiceId", "note", "mobileCoin")
        class MobileCoin(_message.Message):
            __slots__ = ("recipientAddress", "amountPicoMob", "feePicoMob", "receipt", "ledgerBlockTimestamp", "ledgerBlockIndex", "spentKeyImages", "outputPublicKeys")
            RECIPIENTADDRESS_FIELD_NUMBER: _ClassVar[int]
            AMOUNTPICOMOB_FIELD_NUMBER: _ClassVar[int]
            FEEPICOMOB_FIELD_NUMBER: _ClassVar[int]
            RECEIPT_FIELD_NUMBER: _ClassVar[int]
            LEDGERBLOCKTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
            LEDGERBLOCKINDEX_FIELD_NUMBER: _ClassVar[int]
            SPENTKEYIMAGES_FIELD_NUMBER: _ClassVar[int]
            OUTPUTPUBLICKEYS_FIELD_NUMBER: _ClassVar[int]
            recipientAddress: bytes
            amountPicoMob: int
            feePicoMob: int
            receipt: bytes
            ledgerBlockTimestamp: int
            ledgerBlockIndex: int
            spentKeyImages: _containers.RepeatedScalarFieldContainer[bytes]
            outputPublicKeys: _containers.RepeatedScalarFieldContainer[bytes]
            def __init__(self, recipientAddress: _Optional[bytes] = ..., amountPicoMob: _Optional[int] = ..., feePicoMob: _Optional[int] = ..., receipt: _Optional[bytes] = ..., ledgerBlockTimestamp: _Optional[int] = ..., ledgerBlockIndex: _Optional[int] = ..., spentKeyImages: _Optional[_Iterable[bytes]] = ..., outputPublicKeys: _Optional[_Iterable[bytes]] = ...) -> None: ...
        RECIPIENTSERVICEID_FIELD_NUMBER: _ClassVar[int]
        NOTE_FIELD_NUMBER: _ClassVar[int]
        MOBILECOIN_FIELD_NUMBER: _ClassVar[int]
        recipientServiceId: str
        note: str
        mobileCoin: SyncMessage.OutgoingPayment.MobileCoin
        def __init__(self, recipientServiceId: _Optional[str] = ..., note: _Optional[str] = ..., mobileCoin: _Optional[_Union[SyncMessage.OutgoingPayment.MobileCoin, _Mapping]] = ...) -> None: ...
    class PniChangeNumber(_message.Message):
        __slots__ = ("identityKeyPair", "signedPreKey", "lastResortKyberPreKey", "registrationId", "newE164")
        IDENTITYKEYPAIR_FIELD_NUMBER: _ClassVar[int]
        SIGNEDPREKEY_FIELD_NUMBER: _ClassVar[int]
        LASTRESORTKYBERPREKEY_FIELD_NUMBER: _ClassVar[int]
        REGISTRATIONID_FIELD_NUMBER: _ClassVar[int]
        NEWE164_FIELD_NUMBER: _ClassVar[int]
        identityKeyPair: bytes
        signedPreKey: bytes
        lastResortKyberPreKey: bytes
        registrationId: int
        newE164: str
        def __init__(self, identityKeyPair: _Optional[bytes] = ..., signedPreKey: _Optional[bytes] = ..., lastResortKyberPreKey: _Optional[bytes] = ..., registrationId: _Optional[int] = ..., newE164: _Optional[str] = ...) -> None: ...
    class CallEvent(_message.Message):
        __slots__ = ("conversationId", "id", "timestamp", "type", "direction", "event")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_TYPE: _ClassVar[SyncMessage.CallEvent.Type]
            AUDIO_CALL: _ClassVar[SyncMessage.CallEvent.Type]
            VIDEO_CALL: _ClassVar[SyncMessage.CallEvent.Type]
            GROUP_CALL: _ClassVar[SyncMessage.CallEvent.Type]
            AD_HOC_CALL: _ClassVar[SyncMessage.CallEvent.Type]
        UNKNOWN_TYPE: SyncMessage.CallEvent.Type
        AUDIO_CALL: SyncMessage.CallEvent.Type
        VIDEO_CALL: SyncMessage.CallEvent.Type
        GROUP_CALL: SyncMessage.CallEvent.Type
        AD_HOC_CALL: SyncMessage.CallEvent.Type
        class Direction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_DIRECTION: _ClassVar[SyncMessage.CallEvent.Direction]
            INCOMING: _ClassVar[SyncMessage.CallEvent.Direction]
            OUTGOING: _ClassVar[SyncMessage.CallEvent.Direction]
        UNKNOWN_DIRECTION: SyncMessage.CallEvent.Direction
        INCOMING: SyncMessage.CallEvent.Direction
        OUTGOING: SyncMessage.CallEvent.Direction
        class Event(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_ACTION: _ClassVar[SyncMessage.CallEvent.Event]
            ACCEPTED: _ClassVar[SyncMessage.CallEvent.Event]
            NOT_ACCEPTED: _ClassVar[SyncMessage.CallEvent.Event]
            DELETE: _ClassVar[SyncMessage.CallEvent.Event]
            OBSERVED: _ClassVar[SyncMessage.CallEvent.Event]
        UNKNOWN_ACTION: SyncMessage.CallEvent.Event
        ACCEPTED: SyncMessage.CallEvent.Event
        NOT_ACCEPTED: SyncMessage.CallEvent.Event
        DELETE: SyncMessage.CallEvent.Event
        OBSERVED: SyncMessage.CallEvent.Event
        CONVERSATIONID_FIELD_NUMBER: _ClassVar[int]
        ID_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        DIRECTION_FIELD_NUMBER: _ClassVar[int]
        EVENT_FIELD_NUMBER: _ClassVar[int]
        conversationId: bytes
        id: int
        timestamp: int
        type: SyncMessage.CallEvent.Type
        direction: SyncMessage.CallEvent.Direction
        event: SyncMessage.CallEvent.Event
        def __init__(self, conversationId: _Optional[bytes] = ..., id: _Optional[int] = ..., timestamp: _Optional[int] = ..., type: _Optional[_Union[SyncMessage.CallEvent.Type, str]] = ..., direction: _Optional[_Union[SyncMessage.CallEvent.Direction, str]] = ..., event: _Optional[_Union[SyncMessage.CallEvent.Event, str]] = ...) -> None: ...
    class CallLinkUpdate(_message.Message):
        __slots__ = ("rootKey", "adminPassKey", "type")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UPDATE: _ClassVar[SyncMessage.CallLinkUpdate.Type]
        UPDATE: SyncMessage.CallLinkUpdate.Type
        ROOTKEY_FIELD_NUMBER: _ClassVar[int]
        ADMINPASSKEY_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        rootKey: bytes
        adminPassKey: bytes
        type: SyncMessage.CallLinkUpdate.Type
        def __init__(self, rootKey: _Optional[bytes] = ..., adminPassKey: _Optional[bytes] = ..., type: _Optional[_Union[SyncMessage.CallLinkUpdate.Type, str]] = ...) -> None: ...
    class CallLogEvent(_message.Message):
        __slots__ = ("type", "timestamp", "conversationId", "callId")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            CLEAR: _ClassVar[SyncMessage.CallLogEvent.Type]
            MARKED_AS_READ: _ClassVar[SyncMessage.CallLogEvent.Type]
            MARKED_AS_READ_IN_CONVERSATION: _ClassVar[SyncMessage.CallLogEvent.Type]
        CLEAR: SyncMessage.CallLogEvent.Type
        MARKED_AS_READ: SyncMessage.CallLogEvent.Type
        MARKED_AS_READ_IN_CONVERSATION: SyncMessage.CallLogEvent.Type
        TYPE_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        CONVERSATIONID_FIELD_NUMBER: _ClassVar[int]
        CALLID_FIELD_NUMBER: _ClassVar[int]
        type: SyncMessage.CallLogEvent.Type
        timestamp: int
        conversationId: bytes
        callId: int
        def __init__(self, type: _Optional[_Union[SyncMessage.CallLogEvent.Type, str]] = ..., timestamp: _Optional[int] = ..., conversationId: _Optional[bytes] = ..., callId: _Optional[int] = ...) -> None: ...
    class DeleteForMe(_message.Message):
        __slots__ = ("messageDeletes", "conversationDeletes", "localOnlyConversationDeletes", "attachmentDeletes")
        class ConversationIdentifier(_message.Message):
            __slots__ = ("threadServiceId", "threadGroupId", "threadE164")
            THREADSERVICEID_FIELD_NUMBER: _ClassVar[int]
            THREADGROUPID_FIELD_NUMBER: _ClassVar[int]
            THREADE164_FIELD_NUMBER: _ClassVar[int]
            threadServiceId: str
            threadGroupId: bytes
            threadE164: str
            def __init__(self, threadServiceId: _Optional[str] = ..., threadGroupId: _Optional[bytes] = ..., threadE164: _Optional[str] = ...) -> None: ...
        class AddressableMessage(_message.Message):
            __slots__ = ("authorServiceId", "authorE164", "sentTimestamp")
            AUTHORSERVICEID_FIELD_NUMBER: _ClassVar[int]
            AUTHORE164_FIELD_NUMBER: _ClassVar[int]
            SENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
            authorServiceId: str
            authorE164: str
            sentTimestamp: int
            def __init__(self, authorServiceId: _Optional[str] = ..., authorE164: _Optional[str] = ..., sentTimestamp: _Optional[int] = ...) -> None: ...
        class MessageDeletes(_message.Message):
            __slots__ = ("conversation", "messages")
            CONVERSATION_FIELD_NUMBER: _ClassVar[int]
            MESSAGES_FIELD_NUMBER: _ClassVar[int]
            conversation: SyncMessage.DeleteForMe.ConversationIdentifier
            messages: _containers.RepeatedCompositeFieldContainer[SyncMessage.DeleteForMe.AddressableMessage]
            def __init__(self, conversation: _Optional[_Union[SyncMessage.DeleteForMe.ConversationIdentifier, _Mapping]] = ..., messages: _Optional[_Iterable[_Union[SyncMessage.DeleteForMe.AddressableMessage, _Mapping]]] = ...) -> None: ...
        class AttachmentDelete(_message.Message):
            __slots__ = ("conversation", "targetMessage", "uuid", "fallbackDigest", "fallbackPlaintextHash")
            CONVERSATION_FIELD_NUMBER: _ClassVar[int]
            TARGETMESSAGE_FIELD_NUMBER: _ClassVar[int]
            UUID_FIELD_NUMBER: _ClassVar[int]
            FALLBACKDIGEST_FIELD_NUMBER: _ClassVar[int]
            FALLBACKPLAINTEXTHASH_FIELD_NUMBER: _ClassVar[int]
            conversation: SyncMessage.DeleteForMe.ConversationIdentifier
            targetMessage: SyncMessage.DeleteForMe.AddressableMessage
            uuid: bytes
            fallbackDigest: bytes
            fallbackPlaintextHash: bytes
            def __init__(self, conversation: _Optional[_Union[SyncMessage.DeleteForMe.ConversationIdentifier, _Mapping]] = ..., targetMessage: _Optional[_Union[SyncMessage.DeleteForMe.AddressableMessage, _Mapping]] = ..., uuid: _Optional[bytes] = ..., fallbackDigest: _Optional[bytes] = ..., fallbackPlaintextHash: _Optional[bytes] = ...) -> None: ...
        class ConversationDelete(_message.Message):
            __slots__ = ("conversation", "mostRecentMessages", "mostRecentNonExpiringMessages", "isFullDelete")
            CONVERSATION_FIELD_NUMBER: _ClassVar[int]
            MOSTRECENTMESSAGES_FIELD_NUMBER: _ClassVar[int]
            MOSTRECENTNONEXPIRINGMESSAGES_FIELD_NUMBER: _ClassVar[int]
            ISFULLDELETE_FIELD_NUMBER: _ClassVar[int]
            conversation: SyncMessage.DeleteForMe.ConversationIdentifier
            mostRecentMessages: _containers.RepeatedCompositeFieldContainer[SyncMessage.DeleteForMe.AddressableMessage]
            mostRecentNonExpiringMessages: _containers.RepeatedCompositeFieldContainer[SyncMessage.DeleteForMe.AddressableMessage]
            isFullDelete: bool
            def __init__(self, conversation: _Optional[_Union[SyncMessage.DeleteForMe.ConversationIdentifier, _Mapping]] = ..., mostRecentMessages: _Optional[_Iterable[_Union[SyncMessage.DeleteForMe.AddressableMessage, _Mapping]]] = ..., mostRecentNonExpiringMessages: _Optional[_Iterable[_Union[SyncMessage.DeleteForMe.AddressableMessage, _Mapping]]] = ..., isFullDelete: bool = ...) -> None: ...
        class LocalOnlyConversationDelete(_message.Message):
            __slots__ = ("conversation",)
            CONVERSATION_FIELD_NUMBER: _ClassVar[int]
            conversation: SyncMessage.DeleteForMe.ConversationIdentifier
            def __init__(self, conversation: _Optional[_Union[SyncMessage.DeleteForMe.ConversationIdentifier, _Mapping]] = ...) -> None: ...
        MESSAGEDELETES_FIELD_NUMBER: _ClassVar[int]
        CONVERSATIONDELETES_FIELD_NUMBER: _ClassVar[int]
        LOCALONLYCONVERSATIONDELETES_FIELD_NUMBER: _ClassVar[int]
        ATTACHMENTDELETES_FIELD_NUMBER: _ClassVar[int]
        messageDeletes: _containers.RepeatedCompositeFieldContainer[SyncMessage.DeleteForMe.MessageDeletes]
        conversationDeletes: _containers.RepeatedCompositeFieldContainer[SyncMessage.DeleteForMe.ConversationDelete]
        localOnlyConversationDeletes: _containers.RepeatedCompositeFieldContainer[SyncMessage.DeleteForMe.LocalOnlyConversationDelete]
        attachmentDeletes: _containers.RepeatedCompositeFieldContainer[SyncMessage.DeleteForMe.AttachmentDelete]
        def __init__(self, messageDeletes: _Optional[_Iterable[_Union[SyncMessage.DeleteForMe.MessageDeletes, _Mapping]]] = ..., conversationDeletes: _Optional[_Iterable[_Union[SyncMessage.DeleteForMe.ConversationDelete, _Mapping]]] = ..., localOnlyConversationDeletes: _Optional[_Iterable[_Union[SyncMessage.DeleteForMe.LocalOnlyConversationDelete, _Mapping]]] = ..., attachmentDeletes: _Optional[_Iterable[_Union[SyncMessage.DeleteForMe.AttachmentDelete, _Mapping]]] = ...) -> None: ...
    SENT_FIELD_NUMBER: _ClassVar[int]
    CONTACTS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    READ_FIELD_NUMBER: _ClassVar[int]
    BLOCKED_FIELD_NUMBER: _ClassVar[int]
    VERIFIED_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    PADDING_FIELD_NUMBER: _ClassVar[int]
    STICKERPACKOPERATION_FIELD_NUMBER: _ClassVar[int]
    VIEWONCEOPEN_FIELD_NUMBER: _ClassVar[int]
    FETCHLATEST_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    MESSAGEREQUESTRESPONSE_FIELD_NUMBER: _ClassVar[int]
    OUTGOINGPAYMENT_FIELD_NUMBER: _ClassVar[int]
    VIEWED_FIELD_NUMBER: _ClassVar[int]
    PNICHANGENUMBER_FIELD_NUMBER: _ClassVar[int]
    CALLEVENT_FIELD_NUMBER: _ClassVar[int]
    CALLLINKUPDATE_FIELD_NUMBER: _ClassVar[int]
    CALLLOGEVENT_FIELD_NUMBER: _ClassVar[int]
    DELETEFORME_FIELD_NUMBER: _ClassVar[int]
    sent: SyncMessage.Sent
    contacts: SyncMessage.Contacts
    request: SyncMessage.Request
    read: _containers.RepeatedCompositeFieldContainer[SyncMessage.Read]
    blocked: SyncMessage.Blocked
    verified: Verified
    configuration: SyncMessage.Configuration
    padding: bytes
    stickerPackOperation: _containers.RepeatedCompositeFieldContainer[SyncMessage.StickerPackOperation]
    viewOnceOpen: SyncMessage.ViewOnceOpen
    fetchLatest: SyncMessage.FetchLatest
    keys: SyncMessage.Keys
    messageRequestResponse: SyncMessage.MessageRequestResponse
    outgoingPayment: SyncMessage.OutgoingPayment
    viewed: _containers.RepeatedCompositeFieldContainer[SyncMessage.Viewed]
    pniChangeNumber: SyncMessage.PniChangeNumber
    callEvent: SyncMessage.CallEvent
    callLinkUpdate: SyncMessage.CallLinkUpdate
    callLogEvent: SyncMessage.CallLogEvent
    deleteForMe: SyncMessage.DeleteForMe
    def __init__(self, sent: _Optional[_Union[SyncMessage.Sent, _Mapping]] = ..., contacts: _Optional[_Union[SyncMessage.Contacts, _Mapping]] = ..., request: _Optional[_Union[SyncMessage.Request, _Mapping]] = ..., read: _Optional[_Iterable[_Union[SyncMessage.Read, _Mapping]]] = ..., blocked: _Optional[_Union[SyncMessage.Blocked, _Mapping]] = ..., verified: _Optional[_Union[Verified, _Mapping]] = ..., configuration: _Optional[_Union[SyncMessage.Configuration, _Mapping]] = ..., padding: _Optional[bytes] = ..., stickerPackOperation: _Optional[_Iterable[_Union[SyncMessage.StickerPackOperation, _Mapping]]] = ..., viewOnceOpen: _Optional[_Union[SyncMessage.ViewOnceOpen, _Mapping]] = ..., fetchLatest: _Optional[_Union[SyncMessage.FetchLatest, _Mapping]] = ..., keys: _Optional[_Union[SyncMessage.Keys, _Mapping]] = ..., messageRequestResponse: _Optional[_Union[SyncMessage.MessageRequestResponse, _Mapping]] = ..., outgoingPayment: _Optional[_Union[SyncMessage.OutgoingPayment, _Mapping]] = ..., viewed: _Optional[_Iterable[_Union[SyncMessage.Viewed, _Mapping]]] = ..., pniChangeNumber: _Optional[_Union[SyncMessage.PniChangeNumber, _Mapping]] = ..., callEvent: _Optional[_Union[SyncMessage.CallEvent, _Mapping]] = ..., callLinkUpdate: _Optional[_Union[SyncMessage.CallLinkUpdate, _Mapping]] = ..., callLogEvent: _Optional[_Union[SyncMessage.CallLogEvent, _Mapping]] = ..., deleteForMe: _Optional[_Union[SyncMessage.DeleteForMe, _Mapping]] = ...) -> None: ...

class AttachmentPointer(_message.Message):
    __slots__ = ("cdnId", "cdnKey", "contentType", "key", "size", "thumbnail", "digest", "incrementalMac", "incrementalMacChunkSize", "fileName", "flags", "width", "height", "caption", "blurHash", "uploadTimestamp", "cdnNumber", "uuid")
    class Flags(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        VOICE_MESSAGE: _ClassVar[AttachmentPointer.Flags]
        BORDERLESS: _ClassVar[AttachmentPointer.Flags]
        GIF: _ClassVar[AttachmentPointer.Flags]
    VOICE_MESSAGE: AttachmentPointer.Flags
    BORDERLESS: AttachmentPointer.Flags
    GIF: AttachmentPointer.Flags
    CDNID_FIELD_NUMBER: _ClassVar[int]
    CDNKEY_FIELD_NUMBER: _ClassVar[int]
    CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    THUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    INCREMENTALMAC_FIELD_NUMBER: _ClassVar[int]
    INCREMENTALMACCHUNKSIZE_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    BLURHASH_FIELD_NUMBER: _ClassVar[int]
    UPLOADTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    CDNNUMBER_FIELD_NUMBER: _ClassVar[int]
    UUID_FIELD_NUMBER: _ClassVar[int]
    cdnId: int
    cdnKey: str
    contentType: str
    key: bytes
    size: int
    thumbnail: bytes
    digest: bytes
    incrementalMac: bytes
    incrementalMacChunkSize: int
    fileName: str
    flags: int
    width: int
    height: int
    caption: str
    blurHash: str
    uploadTimestamp: int
    cdnNumber: int
    uuid: bytes
    def __init__(self, cdnId: _Optional[int] = ..., cdnKey: _Optional[str] = ..., contentType: _Optional[str] = ..., key: _Optional[bytes] = ..., size: _Optional[int] = ..., thumbnail: _Optional[bytes] = ..., digest: _Optional[bytes] = ..., incrementalMac: _Optional[bytes] = ..., incrementalMacChunkSize: _Optional[int] = ..., fileName: _Optional[str] = ..., flags: _Optional[int] = ..., width: _Optional[int] = ..., height: _Optional[int] = ..., caption: _Optional[str] = ..., blurHash: _Optional[str] = ..., uploadTimestamp: _Optional[int] = ..., cdnNumber: _Optional[int] = ..., uuid: _Optional[bytes] = ...) -> None: ...

class GroupContext(_message.Message):
    __slots__ = ("id", "type", "name", "membersE164", "members", "avatar")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[GroupContext.Type]
        UPDATE: _ClassVar[GroupContext.Type]
        DELIVER: _ClassVar[GroupContext.Type]
        QUIT: _ClassVar[GroupContext.Type]
        REQUEST_INFO: _ClassVar[GroupContext.Type]
    UNKNOWN: GroupContext.Type
    UPDATE: GroupContext.Type
    DELIVER: GroupContext.Type
    QUIT: GroupContext.Type
    REQUEST_INFO: GroupContext.Type
    class Member(_message.Message):
        __slots__ = ("e164",)
        E164_FIELD_NUMBER: _ClassVar[int]
        e164: str
        def __init__(self, e164: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    MEMBERSE164_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    id: bytes
    type: GroupContext.Type
    name: str
    membersE164: _containers.RepeatedScalarFieldContainer[str]
    members: _containers.RepeatedCompositeFieldContainer[GroupContext.Member]
    avatar: AttachmentPointer
    def __init__(self, id: _Optional[bytes] = ..., type: _Optional[_Union[GroupContext.Type, str]] = ..., name: _Optional[str] = ..., membersE164: _Optional[_Iterable[str]] = ..., members: _Optional[_Iterable[_Union[GroupContext.Member, _Mapping]]] = ..., avatar: _Optional[_Union[AttachmentPointer, _Mapping]] = ...) -> None: ...

class GroupContextV2(_message.Message):
    __slots__ = ("masterKey", "revision", "groupChange")
    MASTERKEY_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    GROUPCHANGE_FIELD_NUMBER: _ClassVar[int]
    masterKey: bytes
    revision: int
    groupChange: bytes
    def __init__(self, masterKey: _Optional[bytes] = ..., revision: _Optional[int] = ..., groupChange: _Optional[bytes] = ...) -> None: ...

class ContactDetails(_message.Message):
    __slots__ = ("number", "aci", "name", "avatar", "color", "verified", "profileKey", "expireTimer", "expireTimerVersion", "inboxPosition", "archived")
    class Avatar(_message.Message):
        __slots__ = ("contentType", "length")
        CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
        LENGTH_FIELD_NUMBER: _ClassVar[int]
        contentType: str
        length: int
        def __init__(self, contentType: _Optional[str] = ..., length: _Optional[int] = ...) -> None: ...
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    ACI_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    VERIFIED_FIELD_NUMBER: _ClassVar[int]
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    EXPIRETIMER_FIELD_NUMBER: _ClassVar[int]
    EXPIRETIMERVERSION_FIELD_NUMBER: _ClassVar[int]
    INBOXPOSITION_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    number: str
    aci: str
    name: str
    avatar: ContactDetails.Avatar
    color: str
    verified: Verified
    profileKey: bytes
    expireTimer: int
    expireTimerVersion: int
    inboxPosition: int
    archived: bool
    def __init__(self, number: _Optional[str] = ..., aci: _Optional[str] = ..., name: _Optional[str] = ..., avatar: _Optional[_Union[ContactDetails.Avatar, _Mapping]] = ..., color: _Optional[str] = ..., verified: _Optional[_Union[Verified, _Mapping]] = ..., profileKey: _Optional[bytes] = ..., expireTimer: _Optional[int] = ..., expireTimerVersion: _Optional[int] = ..., inboxPosition: _Optional[int] = ..., archived: bool = ...) -> None: ...

class GroupDetails(_message.Message):
    __slots__ = ("id", "name", "membersE164", "members", "avatar", "active", "expireTimer", "color", "blocked", "inboxPosition", "archived")
    class Avatar(_message.Message):
        __slots__ = ("contentType", "length")
        CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
        LENGTH_FIELD_NUMBER: _ClassVar[int]
        contentType: str
        length: int
        def __init__(self, contentType: _Optional[str] = ..., length: _Optional[int] = ...) -> None: ...
    class Member(_message.Message):
        __slots__ = ("e164",)
        E164_FIELD_NUMBER: _ClassVar[int]
        e164: str
        def __init__(self, e164: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    MEMBERSE164_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    EXPIRETIMER_FIELD_NUMBER: _ClassVar[int]
    COLOR_FIELD_NUMBER: _ClassVar[int]
    BLOCKED_FIELD_NUMBER: _ClassVar[int]
    INBOXPOSITION_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    id: bytes
    name: str
    membersE164: _containers.RepeatedScalarFieldContainer[str]
    members: _containers.RepeatedCompositeFieldContainer[GroupDetails.Member]
    avatar: GroupDetails.Avatar
    active: bool
    expireTimer: int
    color: str
    blocked: bool
    inboxPosition: int
    archived: bool
    def __init__(self, id: _Optional[bytes] = ..., name: _Optional[str] = ..., membersE164: _Optional[_Iterable[str]] = ..., members: _Optional[_Iterable[_Union[GroupDetails.Member, _Mapping]]] = ..., avatar: _Optional[_Union[GroupDetails.Avatar, _Mapping]] = ..., active: bool = ..., expireTimer: _Optional[int] = ..., color: _Optional[str] = ..., blocked: bool = ..., inboxPosition: _Optional[int] = ..., archived: bool = ...) -> None: ...

class PaymentAddress(_message.Message):
    __slots__ = ("mobileCoinAddress",)
    class MobileCoinAddress(_message.Message):
        __slots__ = ("address", "signature")
        ADDRESS_FIELD_NUMBER: _ClassVar[int]
        SIGNATURE_FIELD_NUMBER: _ClassVar[int]
        address: bytes
        signature: bytes
        def __init__(self, address: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...
    MOBILECOINADDRESS_FIELD_NUMBER: _ClassVar[int]
    mobileCoinAddress: PaymentAddress.MobileCoinAddress
    def __init__(self, mobileCoinAddress: _Optional[_Union[PaymentAddress.MobileCoinAddress, _Mapping]] = ...) -> None: ...

class DecryptionErrorMessage(_message.Message):
    __slots__ = ("ratchetKey", "timestamp", "deviceId")
    RATCHETKEY_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    DEVICEID_FIELD_NUMBER: _ClassVar[int]
    ratchetKey: bytes
    timestamp: int
    deviceId: int
    def __init__(self, ratchetKey: _Optional[bytes] = ..., timestamp: _Optional[int] = ..., deviceId: _Optional[int] = ...) -> None: ...

class PniSignatureMessage(_message.Message):
    __slots__ = ("pni", "signature")
    PNI_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    pni: bytes
    signature: bytes
    def __init__(self, pni: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class EditMessage(_message.Message):
    __slots__ = ("targetSentTimestamp", "dataMessage")
    TARGETSENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    DATAMESSAGE_FIELD_NUMBER: _ClassVar[int]
    targetSentTimestamp: int
    dataMessage: DataMessage
    def __init__(self, targetSentTimestamp: _Optional[int] = ..., dataMessage: _Optional[_Union[DataMessage, _Mapping]] = ...) -> None: ...
