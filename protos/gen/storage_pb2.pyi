from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SessionStructure(_message.Message):
    __slots__ = ("session_version", "local_identity_public", "remote_identity_public", "root_key", "previous_counter", "sender_chain", "receiver_chains", "pending_pre_key", "pending_kyber_pre_key", "remote_registration_id", "local_registration_id", "alice_base_key")
    class Chain(_message.Message):
        __slots__ = ("sender_ratchet_key", "sender_ratchet_key_private", "chain_key", "message_keys")
        class ChainKey(_message.Message):
            __slots__ = ("index", "key")
            INDEX_FIELD_NUMBER: _ClassVar[int]
            KEY_FIELD_NUMBER: _ClassVar[int]
            index: int
            key: bytes
            def __init__(self, index: _Optional[int] = ..., key: _Optional[bytes] = ...) -> None: ...
        class MessageKey(_message.Message):
            __slots__ = ("index", "cipher_key", "mac_key", "iv")
            INDEX_FIELD_NUMBER: _ClassVar[int]
            CIPHER_KEY_FIELD_NUMBER: _ClassVar[int]
            MAC_KEY_FIELD_NUMBER: _ClassVar[int]
            IV_FIELD_NUMBER: _ClassVar[int]
            index: int
            cipher_key: bytes
            mac_key: bytes
            iv: bytes
            def __init__(self, index: _Optional[int] = ..., cipher_key: _Optional[bytes] = ..., mac_key: _Optional[bytes] = ..., iv: _Optional[bytes] = ...) -> None: ...
        SENDER_RATCHET_KEY_FIELD_NUMBER: _ClassVar[int]
        SENDER_RATCHET_KEY_PRIVATE_FIELD_NUMBER: _ClassVar[int]
        CHAIN_KEY_FIELD_NUMBER: _ClassVar[int]
        MESSAGE_KEYS_FIELD_NUMBER: _ClassVar[int]
        sender_ratchet_key: bytes
        sender_ratchet_key_private: bytes
        chain_key: SessionStructure.Chain.ChainKey
        message_keys: _containers.RepeatedCompositeFieldContainer[SessionStructure.Chain.MessageKey]
        def __init__(self, sender_ratchet_key: _Optional[bytes] = ..., sender_ratchet_key_private: _Optional[bytes] = ..., chain_key: _Optional[_Union[SessionStructure.Chain.ChainKey, _Mapping]] = ..., message_keys: _Optional[_Iterable[_Union[SessionStructure.Chain.MessageKey, _Mapping]]] = ...) -> None: ...
    class PendingPreKey(_message.Message):
        __slots__ = ("pre_key_id", "signed_pre_key_id", "base_key", "timestamp")
        PRE_KEY_ID_FIELD_NUMBER: _ClassVar[int]
        SIGNED_PRE_KEY_ID_FIELD_NUMBER: _ClassVar[int]
        BASE_KEY_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        pre_key_id: int
        signed_pre_key_id: int
        base_key: bytes
        timestamp: int
        def __init__(self, pre_key_id: _Optional[int] = ..., signed_pre_key_id: _Optional[int] = ..., base_key: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...
    class PendingKyberPreKey(_message.Message):
        __slots__ = ("pre_key_id", "ciphertext")
        PRE_KEY_ID_FIELD_NUMBER: _ClassVar[int]
        CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
        pre_key_id: int
        ciphertext: bytes
        def __init__(self, pre_key_id: _Optional[int] = ..., ciphertext: _Optional[bytes] = ...) -> None: ...
    SESSION_VERSION_FIELD_NUMBER: _ClassVar[int]
    LOCAL_IDENTITY_PUBLIC_FIELD_NUMBER: _ClassVar[int]
    REMOTE_IDENTITY_PUBLIC_FIELD_NUMBER: _ClassVar[int]
    ROOT_KEY_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_COUNTER_FIELD_NUMBER: _ClassVar[int]
    SENDER_CHAIN_FIELD_NUMBER: _ClassVar[int]
    RECEIVER_CHAINS_FIELD_NUMBER: _ClassVar[int]
    PENDING_PRE_KEY_FIELD_NUMBER: _ClassVar[int]
    PENDING_KYBER_PRE_KEY_FIELD_NUMBER: _ClassVar[int]
    REMOTE_REGISTRATION_ID_FIELD_NUMBER: _ClassVar[int]
    LOCAL_REGISTRATION_ID_FIELD_NUMBER: _ClassVar[int]
    ALICE_BASE_KEY_FIELD_NUMBER: _ClassVar[int]
    session_version: int
    local_identity_public: bytes
    remote_identity_public: bytes
    root_key: bytes
    previous_counter: int
    sender_chain: SessionStructure.Chain
    receiver_chains: _containers.RepeatedCompositeFieldContainer[SessionStructure.Chain]
    pending_pre_key: SessionStructure.PendingPreKey
    pending_kyber_pre_key: SessionStructure.PendingKyberPreKey
    remote_registration_id: int
    local_registration_id: int
    alice_base_key: bytes
    def __init__(self, session_version: _Optional[int] = ..., local_identity_public: _Optional[bytes] = ..., remote_identity_public: _Optional[bytes] = ..., root_key: _Optional[bytes] = ..., previous_counter: _Optional[int] = ..., sender_chain: _Optional[_Union[SessionStructure.Chain, _Mapping]] = ..., receiver_chains: _Optional[_Iterable[_Union[SessionStructure.Chain, _Mapping]]] = ..., pending_pre_key: _Optional[_Union[SessionStructure.PendingPreKey, _Mapping]] = ..., pending_kyber_pre_key: _Optional[_Union[SessionStructure.PendingKyberPreKey, _Mapping]] = ..., remote_registration_id: _Optional[int] = ..., local_registration_id: _Optional[int] = ..., alice_base_key: _Optional[bytes] = ...) -> None: ...

class RecordStructure(_message.Message):
    __slots__ = ("current_session", "previous_sessions")
    CURRENT_SESSION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_SESSIONS_FIELD_NUMBER: _ClassVar[int]
    current_session: SessionStructure
    previous_sessions: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, current_session: _Optional[_Union[SessionStructure, _Mapping]] = ..., previous_sessions: _Optional[_Iterable[bytes]] = ...) -> None: ...

class PreKeyRecordStructure(_message.Message):
    __slots__ = ("id", "public_key", "private_key")
    ID_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    id: int
    public_key: bytes
    private_key: bytes
    def __init__(self, id: _Optional[int] = ..., public_key: _Optional[bytes] = ..., private_key: _Optional[bytes] = ...) -> None: ...

class SignedPreKeyRecordStructure(_message.Message):
    __slots__ = ("id", "public_key", "private_key", "signature", "timestamp")
    ID_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    id: int
    public_key: bytes
    private_key: bytes
    signature: bytes
    timestamp: int
    def __init__(self, id: _Optional[int] = ..., public_key: _Optional[bytes] = ..., private_key: _Optional[bytes] = ..., signature: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...

class IdentityKeyPairStructure(_message.Message):
    __slots__ = ("public_key", "private_key")
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    public_key: bytes
    private_key: bytes
    def __init__(self, public_key: _Optional[bytes] = ..., private_key: _Optional[bytes] = ...) -> None: ...

class SenderKeyStateStructure(_message.Message):
    __slots__ = ("message_version", "chain_id", "sender_chain_key", "sender_signing_key", "sender_message_keys")
    class SenderChainKey(_message.Message):
        __slots__ = ("iteration", "seed")
        ITERATION_FIELD_NUMBER: _ClassVar[int]
        SEED_FIELD_NUMBER: _ClassVar[int]
        iteration: int
        seed: bytes
        def __init__(self, iteration: _Optional[int] = ..., seed: _Optional[bytes] = ...) -> None: ...
    class SenderMessageKey(_message.Message):
        __slots__ = ("iteration", "seed")
        ITERATION_FIELD_NUMBER: _ClassVar[int]
        SEED_FIELD_NUMBER: _ClassVar[int]
        iteration: int
        seed: bytes
        def __init__(self, iteration: _Optional[int] = ..., seed: _Optional[bytes] = ...) -> None: ...
    class SenderSigningKey(_message.Message):
        __slots__ = ("public", "private")
        PUBLIC_FIELD_NUMBER: _ClassVar[int]
        PRIVATE_FIELD_NUMBER: _ClassVar[int]
        public: bytes
        private: bytes
        def __init__(self, public: _Optional[bytes] = ..., private: _Optional[bytes] = ...) -> None: ...
    MESSAGE_VERSION_FIELD_NUMBER: _ClassVar[int]
    CHAIN_ID_FIELD_NUMBER: _ClassVar[int]
    SENDER_CHAIN_KEY_FIELD_NUMBER: _ClassVar[int]
    SENDER_SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    SENDER_MESSAGE_KEYS_FIELD_NUMBER: _ClassVar[int]
    message_version: int
    chain_id: int
    sender_chain_key: SenderKeyStateStructure.SenderChainKey
    sender_signing_key: SenderKeyStateStructure.SenderSigningKey
    sender_message_keys: _containers.RepeatedCompositeFieldContainer[SenderKeyStateStructure.SenderMessageKey]
    def __init__(self, message_version: _Optional[int] = ..., chain_id: _Optional[int] = ..., sender_chain_key: _Optional[_Union[SenderKeyStateStructure.SenderChainKey, _Mapping]] = ..., sender_signing_key: _Optional[_Union[SenderKeyStateStructure.SenderSigningKey, _Mapping]] = ..., sender_message_keys: _Optional[_Iterable[_Union[SenderKeyStateStructure.SenderMessageKey, _Mapping]]] = ...) -> None: ...

class SenderKeyRecordStructure(_message.Message):
    __slots__ = ("sender_key_states",)
    SENDER_KEY_STATES_FIELD_NUMBER: _ClassVar[int]
    sender_key_states: _containers.RepeatedCompositeFieldContainer[SenderKeyStateStructure]
    def __init__(self, sender_key_states: _Optional[_Iterable[_Union[SenderKeyStateStructure, _Mapping]]] = ...) -> None: ...
