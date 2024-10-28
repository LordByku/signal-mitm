from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ServerCertificate(_message.Message):
    __slots__ = ("certificate", "signature")
    class Certificate(_message.Message):
        __slots__ = ("id", "key")
        ID_FIELD_NUMBER: _ClassVar[int]
        KEY_FIELD_NUMBER: _ClassVar[int]
        id: int
        key: bytes
        def __init__(self, id: _Optional[int] = ..., key: _Optional[bytes] = ...) -> None: ...
    CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    certificate: bytes
    signature: bytes
    def __init__(self, certificate: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class SenderCertificate(_message.Message):
    __slots__ = ("certificate", "signature")
    class Certificate(_message.Message):
        __slots__ = ("senderE164", "senderUuid", "senderDevice", "expires", "identityKey", "signer")
        SENDERE164_FIELD_NUMBER: _ClassVar[int]
        SENDERUUID_FIELD_NUMBER: _ClassVar[int]
        SENDERDEVICE_FIELD_NUMBER: _ClassVar[int]
        EXPIRES_FIELD_NUMBER: _ClassVar[int]
        IDENTITYKEY_FIELD_NUMBER: _ClassVar[int]
        SIGNER_FIELD_NUMBER: _ClassVar[int]
        senderE164: str
        senderUuid: str
        senderDevice: int
        expires: int
        identityKey: bytes
        signer: ServerCertificate
        def __init__(self, senderE164: _Optional[str] = ..., senderUuid: _Optional[str] = ..., senderDevice: _Optional[int] = ..., expires: _Optional[int] = ..., identityKey: _Optional[bytes] = ..., signer: _Optional[_Union[ServerCertificate, _Mapping]] = ...) -> None: ...
    CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    certificate: bytes
    signature: bytes
    def __init__(self, certificate: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class UnidentifiedSenderMessage(_message.Message):
    __slots__ = ("ephemeralPublic", "encryptedStatic", "encryptedMessage")
    class Message(_message.Message):
        __slots__ = ("type", "senderCertificate", "content", "contentHint", "groupId")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            PREKEY_MESSAGE: _ClassVar[UnidentifiedSenderMessage.Message.Type]
            MESSAGE: _ClassVar[UnidentifiedSenderMessage.Message.Type]
            SENDERKEY_MESSAGE: _ClassVar[UnidentifiedSenderMessage.Message.Type]
            PLAINTEXT_CONTENT: _ClassVar[UnidentifiedSenderMessage.Message.Type]
        PREKEY_MESSAGE: UnidentifiedSenderMessage.Message.Type
        MESSAGE: UnidentifiedSenderMessage.Message.Type
        SENDERKEY_MESSAGE: UnidentifiedSenderMessage.Message.Type
        PLAINTEXT_CONTENT: UnidentifiedSenderMessage.Message.Type
        class ContentHint(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            RESENDABLE: _ClassVar[UnidentifiedSenderMessage.Message.ContentHint]
            IMPLICIT: _ClassVar[UnidentifiedSenderMessage.Message.ContentHint]
        RESENDABLE: UnidentifiedSenderMessage.Message.ContentHint
        IMPLICIT: UnidentifiedSenderMessage.Message.ContentHint
        TYPE_FIELD_NUMBER: _ClassVar[int]
        SENDERCERTIFICATE_FIELD_NUMBER: _ClassVar[int]
        CONTENT_FIELD_NUMBER: _ClassVar[int]
        CONTENTHINT_FIELD_NUMBER: _ClassVar[int]
        GROUPID_FIELD_NUMBER: _ClassVar[int]
        type: UnidentifiedSenderMessage.Message.Type
        senderCertificate: bytes
        content: bytes
        contentHint: UnidentifiedSenderMessage.Message.ContentHint
        groupId: bytes
        def __init__(self, type: _Optional[_Union[UnidentifiedSenderMessage.Message.Type, str]] = ..., senderCertificate: _Optional[bytes] = ..., content: _Optional[bytes] = ..., contentHint: _Optional[_Union[UnidentifiedSenderMessage.Message.ContentHint, str]] = ..., groupId: _Optional[bytes] = ...) -> None: ...
    EPHEMERALPUBLIC_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDSTATIC_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ephemeralPublic: bytes
    encryptedStatic: bytes
    encryptedMessage: bytes
    def __init__(self, ephemeralPublic: _Optional[bytes] = ..., encryptedStatic: _Optional[bytes] = ..., encryptedMessage: _Optional[bytes] = ...) -> None: ...
