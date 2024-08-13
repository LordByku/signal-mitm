from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class ClientRequest(_message.Message):
    __slots__ = ("aci_uak_pairs", "prev_e164s", "new_e164s", "discard_e164s", "token", "token_ack", "return_acis_without_uaks")
    ACI_UAK_PAIRS_FIELD_NUMBER: _ClassVar[int]
    PREV_E164S_FIELD_NUMBER: _ClassVar[int]
    NEW_E164S_FIELD_NUMBER: _ClassVar[int]
    DISCARD_E164S_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    TOKEN_ACK_FIELD_NUMBER: _ClassVar[int]
    RETURN_ACIS_WITHOUT_UAKS_FIELD_NUMBER: _ClassVar[int]
    aci_uak_pairs: bytes
    prev_e164s: bytes
    new_e164s: bytes
    discard_e164s: bytes
    token: bytes
    token_ack: bool
    return_acis_without_uaks: bool
    def __init__(self, aci_uak_pairs: _Optional[bytes] = ..., prev_e164s: _Optional[bytes] = ..., new_e164s: _Optional[bytes] = ..., discard_e164s: _Optional[bytes] = ..., token: _Optional[bytes] = ..., token_ack: bool = ..., return_acis_without_uaks: bool = ...) -> None: ...

class ClientResponse(_message.Message):
    __slots__ = ("e164_pni_aci_triples", "token", "debug_permits_used")
    E164_PNI_ACI_TRIPLES_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    DEBUG_PERMITS_USED_FIELD_NUMBER: _ClassVar[int]
    e164_pni_aci_triples: bytes
    token: bytes
    debug_permits_used: int
    def __init__(self, e164_pni_aci_triples: _Optional[bytes] = ..., token: _Optional[bytes] = ..., debug_permits_used: _Optional[int] = ...) -> None: ...
