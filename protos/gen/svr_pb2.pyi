from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ClientHandshakeStart(_message.Message):
    __slots__ = ("evidence", "endorsement")
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    ENDORSEMENT_FIELD_NUMBER: _ClassVar[int]
    evidence: bytes
    endorsement: bytes
    def __init__(self, evidence: _Optional[bytes] = ..., endorsement: _Optional[bytes] = ...) -> None: ...

class RaftGroupConfig(_message.Message):
    __slots__ = ("group_id", "min_voting_replicas", "max_voting_replicas", "super_majority")
    GROUP_ID_FIELD_NUMBER: _ClassVar[int]
    MIN_VOTING_REPLICAS_FIELD_NUMBER: _ClassVar[int]
    MAX_VOTING_REPLICAS_FIELD_NUMBER: _ClassVar[int]
    SUPER_MAJORITY_FIELD_NUMBER: _ClassVar[int]
    group_id: int
    min_voting_replicas: int
    max_voting_replicas: int
    super_majority: int
    def __init__(self, group_id: _Optional[int] = ..., min_voting_replicas: _Optional[int] = ..., max_voting_replicas: _Optional[int] = ..., super_majority: _Optional[int] = ...) -> None: ...

class AttestationData(_message.Message):
    __slots__ = ("public_key", "group_config")
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    GROUP_CONFIG_FIELD_NUMBER: _ClassVar[int]
    public_key: bytes
    group_config: RaftGroupConfig
    def __init__(self, public_key: _Optional[bytes] = ..., group_config: _Optional[_Union[RaftGroupConfig, _Mapping]] = ...) -> None: ...
