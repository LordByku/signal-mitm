from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class Content(_message.Message):
    __slots__ = ("data_message", "sync_message", "call_message", "null_message", "receipt_message", "typing_message", "sender_key_distribution_message", "decryption_error_message")
    DATA_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SYNC_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    CALL_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    NULL_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TYPING_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SENDER_KEY_DISTRIBUTION_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    DECRYPTION_ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    data_message: bytes
    sync_message: bytes
    call_message: bytes
    null_message: bytes
    receipt_message: bytes
    typing_message: bytes
    sender_key_distribution_message: bytes
    decryption_error_message: bytes
    def __init__(self, data_message: _Optional[bytes] = ..., sync_message: _Optional[bytes] = ..., call_message: _Optional[bytes] = ..., null_message: _Optional[bytes] = ..., receipt_message: _Optional[bytes] = ..., typing_message: _Optional[bytes] = ..., sender_key_distribution_message: _Optional[bytes] = ..., decryption_error_message: _Optional[bytes] = ...) -> None: ...

class DecryptionErrorMessage(_message.Message):
    __slots__ = ("ratchet_key", "timestamp", "device_id")
    RATCHET_KEY_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    ratchet_key: bytes
    timestamp: int
    device_id: int
    def __init__(self, ratchet_key: _Optional[bytes] = ..., timestamp: _Optional[int] = ..., device_id: _Optional[int] = ...) -> None: ...
