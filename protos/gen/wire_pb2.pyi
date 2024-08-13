from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class SignalMessage(_message.Message):
    __slots__ = ("ratchet_key", "counter", "previous_counter", "ciphertext")
    RATCHET_KEY_FIELD_NUMBER: _ClassVar[int]
    COUNTER_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_COUNTER_FIELD_NUMBER: _ClassVar[int]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    ratchet_key: bytes
    counter: int
    previous_counter: int
    ciphertext: bytes
    def __init__(self, ratchet_key: _Optional[bytes] = ..., counter: _Optional[int] = ..., previous_counter: _Optional[int] = ..., ciphertext: _Optional[bytes] = ...) -> None: ...

class PreKeySignalMessage(_message.Message):
    __slots__ = ("registration_id", "pre_key_id", "signed_pre_key_id", "kyber_pre_key_id", "kyber_ciphertext", "base_key", "identity_key", "message")
    REGISTRATION_ID_FIELD_NUMBER: _ClassVar[int]
    PRE_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    SIGNED_PRE_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    KYBER_PRE_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    KYBER_CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    BASE_KEY_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_KEY_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    registration_id: int
    pre_key_id: int
    signed_pre_key_id: int
    kyber_pre_key_id: int
    kyber_ciphertext: bytes
    base_key: bytes
    identity_key: bytes
    message: bytes
    def __init__(self, registration_id: _Optional[int] = ..., pre_key_id: _Optional[int] = ..., signed_pre_key_id: _Optional[int] = ..., kyber_pre_key_id: _Optional[int] = ..., kyber_ciphertext: _Optional[bytes] = ..., base_key: _Optional[bytes] = ..., identity_key: _Optional[bytes] = ..., message: _Optional[bytes] = ...) -> None: ...

class SenderKeyMessage(_message.Message):
    __slots__ = ("distribution_uuid", "chain_id", "iteration", "ciphertext")
    DISTRIBUTION_UUID_FIELD_NUMBER: _ClassVar[int]
    CHAIN_ID_FIELD_NUMBER: _ClassVar[int]
    ITERATION_FIELD_NUMBER: _ClassVar[int]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    distribution_uuid: bytes
    chain_id: int
    iteration: int
    ciphertext: bytes
    def __init__(self, distribution_uuid: _Optional[bytes] = ..., chain_id: _Optional[int] = ..., iteration: _Optional[int] = ..., ciphertext: _Optional[bytes] = ...) -> None: ...

class SenderKeyDistributionMessage(_message.Message):
    __slots__ = ("distribution_uuid", "chain_id", "iteration", "chain_key", "signing_key")
    DISTRIBUTION_UUID_FIELD_NUMBER: _ClassVar[int]
    CHAIN_ID_FIELD_NUMBER: _ClassVar[int]
    ITERATION_FIELD_NUMBER: _ClassVar[int]
    CHAIN_KEY_FIELD_NUMBER: _ClassVar[int]
    SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    distribution_uuid: bytes
    chain_id: int
    iteration: int
    chain_key: bytes
    signing_key: bytes
    def __init__(self, distribution_uuid: _Optional[bytes] = ..., chain_id: _Optional[int] = ..., iteration: _Optional[int] = ..., chain_key: _Optional[bytes] = ..., signing_key: _Optional[bytes] = ...) -> None: ...
