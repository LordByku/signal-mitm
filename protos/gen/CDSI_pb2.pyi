from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class ClientRequest(_message.Message):
    __slots__ = ("aciUakPairs", "prevE164s", "newE164s", "discardE164s", "token", "tokenAck", "returnAcisWithoutUaks")
    ACIUAKPAIRS_FIELD_NUMBER: _ClassVar[int]
    PREVE164S_FIELD_NUMBER: _ClassVar[int]
    NEWE164S_FIELD_NUMBER: _ClassVar[int]
    DISCARDE164S_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    TOKENACK_FIELD_NUMBER: _ClassVar[int]
    RETURNACISWITHOUTUAKS_FIELD_NUMBER: _ClassVar[int]
    aciUakPairs: bytes
    prevE164s: bytes
    newE164s: bytes
    discardE164s: bytes
    token: bytes
    tokenAck: bool
    returnAcisWithoutUaks: bool
    def __init__(self, aciUakPairs: _Optional[bytes] = ..., prevE164s: _Optional[bytes] = ..., newE164s: _Optional[bytes] = ..., discardE164s: _Optional[bytes] = ..., token: _Optional[bytes] = ..., tokenAck: bool = ..., returnAcisWithoutUaks: bool = ...) -> None: ...

class ClientResponse(_message.Message):
    __slots__ = ("e164PniAciTriples", "retryAfterSecs", "token", "debugPermitsUsed")
    E164PNIACITRIPLES_FIELD_NUMBER: _ClassVar[int]
    RETRYAFTERSECS_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    DEBUGPERMITSUSED_FIELD_NUMBER: _ClassVar[int]
    e164PniAciTriples: bytes
    retryAfterSecs: int
    token: bytes
    debugPermitsUsed: int
    def __init__(self, e164PniAciTriples: _Optional[bytes] = ..., retryAfterSecs: _Optional[int] = ..., token: _Optional[bytes] = ..., debugPermitsUsed: _Optional[int] = ...) -> None: ...

class EnclaveLoad(_message.Message):
    __slots__ = ("clearAll", "e164AciPniUakTuples", "sharedTokenSecret")
    CLEARALL_FIELD_NUMBER: _ClassVar[int]
    E164ACIPNIUAKTUPLES_FIELD_NUMBER: _ClassVar[int]
    SHAREDTOKENSECRET_FIELD_NUMBER: _ClassVar[int]
    clearAll: bool
    e164AciPniUakTuples: bytes
    sharedTokenSecret: bytes
    def __init__(self, clearAll: bool = ..., e164AciPniUakTuples: _Optional[bytes] = ..., sharedTokenSecret: _Optional[bytes] = ...) -> None: ...

class ClientHandshakeStart(_message.Message):
    __slots__ = ("testonlyPubkey", "evidence", "endorsement")
    TESTONLYPUBKEY_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    ENDORSEMENT_FIELD_NUMBER: _ClassVar[int]
    testonlyPubkey: bytes
    evidence: bytes
    endorsement: bytes
    def __init__(self, testonlyPubkey: _Optional[bytes] = ..., evidence: _Optional[bytes] = ..., endorsement: _Optional[bytes] = ...) -> None: ...
