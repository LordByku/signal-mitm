from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class ProvisioningVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INITIAL: _ClassVar[ProvisioningVersion]
    TABLET_SUPPORT: _ClassVar[ProvisioningVersion]
    CURRENT: _ClassVar[ProvisioningVersion]
INITIAL: ProvisioningVersion
TABLET_SUPPORT: ProvisioningVersion
CURRENT: ProvisioningVersion

class ProvisioningUuid(_message.Message):
    __slots__ = ("uuid",)
    UUID_FIELD_NUMBER: _ClassVar[int]
    uuid: str
    def __init__(self, uuid: _Optional[str] = ...) -> None: ...

class ProvisionEnvelope(_message.Message):
    __slots__ = ("publicKey", "body")
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    publicKey: bytes
    body: bytes
    def __init__(self, publicKey: _Optional[bytes] = ..., body: _Optional[bytes] = ...) -> None: ...

class ProvisionMessage(_message.Message):
    __slots__ = ("aciIdentityKeyPublic", "aciIdentityKeyPrivate", "pniIdentityKeyPublic", "pniIdentityKeyPrivate", "aci", "pni", "number", "provisioningCode", "userAgent", "profileKey", "readReceipts", "provisioningVersion", "masterKey")
    ACIIDENTITYKEYPUBLIC_FIELD_NUMBER: _ClassVar[int]
    ACIIDENTITYKEYPRIVATE_FIELD_NUMBER: _ClassVar[int]
    PNIIDENTITYKEYPUBLIC_FIELD_NUMBER: _ClassVar[int]
    PNIIDENTITYKEYPRIVATE_FIELD_NUMBER: _ClassVar[int]
    ACI_FIELD_NUMBER: _ClassVar[int]
    PNI_FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    PROVISIONINGCODE_FIELD_NUMBER: _ClassVar[int]
    USERAGENT_FIELD_NUMBER: _ClassVar[int]
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    READRECEIPTS_FIELD_NUMBER: _ClassVar[int]
    PROVISIONINGVERSION_FIELD_NUMBER: _ClassVar[int]
    MASTERKEY_FIELD_NUMBER: _ClassVar[int]
    aciIdentityKeyPublic: bytes
    aciIdentityKeyPrivate: bytes
    pniIdentityKeyPublic: bytes
    pniIdentityKeyPrivate: bytes
    aci: str
    pni: str
    number: str
    provisioningCode: str
    userAgent: str
    profileKey: bytes
    readReceipts: bool
    provisioningVersion: int
    masterKey: bytes
    def __init__(self, aciIdentityKeyPublic: _Optional[bytes] = ..., aciIdentityKeyPrivate: _Optional[bytes] = ..., pniIdentityKeyPublic: _Optional[bytes] = ..., pniIdentityKeyPrivate: _Optional[bytes] = ..., aci: _Optional[str] = ..., pni: _Optional[str] = ..., number: _Optional[str] = ..., provisioningCode: _Optional[str] = ..., userAgent: _Optional[str] = ..., profileKey: _Optional[bytes] = ..., readReceipts: bool = ..., provisioningVersion: _Optional[int] = ..., masterKey: _Optional[bytes] = ...) -> None: ...
