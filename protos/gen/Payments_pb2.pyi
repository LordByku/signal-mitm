from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MobileCoinLedger(_message.Message):
    __slots__ = ("deprecatedBalance", "balance", "deprecatedTransferableBalance", "transferableBalance", "highestBlock", "asOfTimeStamp", "spentTxos", "unspentTxos")
    class OwnedTXO(_message.Message):
        __slots__ = ("deprecatedAmount", "amount", "keyImage", "publicKey", "receivedInBlock", "spentInBlock")
        DEPRECATEDAMOUNT_FIELD_NUMBER: _ClassVar[int]
        AMOUNT_FIELD_NUMBER: _ClassVar[int]
        KEYIMAGE_FIELD_NUMBER: _ClassVar[int]
        PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
        RECEIVEDINBLOCK_FIELD_NUMBER: _ClassVar[int]
        SPENTINBLOCK_FIELD_NUMBER: _ClassVar[int]
        deprecatedAmount: int
        amount: bytes
        keyImage: bytes
        publicKey: bytes
        receivedInBlock: MobileCoinLedger.Block
        spentInBlock: MobileCoinLedger.Block
        def __init__(self, deprecatedAmount: _Optional[int] = ..., amount: _Optional[bytes] = ..., keyImage: _Optional[bytes] = ..., publicKey: _Optional[bytes] = ..., receivedInBlock: _Optional[_Union[MobileCoinLedger.Block, _Mapping]] = ..., spentInBlock: _Optional[_Union[MobileCoinLedger.Block, _Mapping]] = ...) -> None: ...
    class Block(_message.Message):
        __slots__ = ("blockNumber", "timestamp")
        BLOCKNUMBER_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        blockNumber: int
        timestamp: int
        def __init__(self, blockNumber: _Optional[int] = ..., timestamp: _Optional[int] = ...) -> None: ...
    DEPRECATEDBALANCE_FIELD_NUMBER: _ClassVar[int]
    BALANCE_FIELD_NUMBER: _ClassVar[int]
    DEPRECATEDTRANSFERABLEBALANCE_FIELD_NUMBER: _ClassVar[int]
    TRANSFERABLEBALANCE_FIELD_NUMBER: _ClassVar[int]
    HIGHESTBLOCK_FIELD_NUMBER: _ClassVar[int]
    ASOFTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SPENTTXOS_FIELD_NUMBER: _ClassVar[int]
    UNSPENTTXOS_FIELD_NUMBER: _ClassVar[int]
    deprecatedBalance: int
    balance: bytes
    deprecatedTransferableBalance: int
    transferableBalance: bytes
    highestBlock: MobileCoinLedger.Block
    asOfTimeStamp: int
    spentTxos: _containers.RepeatedCompositeFieldContainer[MobileCoinLedger.OwnedTXO]
    unspentTxos: _containers.RepeatedCompositeFieldContainer[MobileCoinLedger.OwnedTXO]
    def __init__(self, deprecatedBalance: _Optional[int] = ..., balance: _Optional[bytes] = ..., deprecatedTransferableBalance: _Optional[int] = ..., transferableBalance: _Optional[bytes] = ..., highestBlock: _Optional[_Union[MobileCoinLedger.Block, _Mapping]] = ..., asOfTimeStamp: _Optional[int] = ..., spentTxos: _Optional[_Iterable[_Union[MobileCoinLedger.OwnedTXO, _Mapping]]] = ..., unspentTxos: _Optional[_Iterable[_Union[MobileCoinLedger.OwnedTXO, _Mapping]]] = ...) -> None: ...

class PaymentMetaData(_message.Message):
    __slots__ = ("mobileCoinTxoIdentification",)
    class MobileCoinTxoIdentification(_message.Message):
        __slots__ = ("publicKey", "keyImages")
        PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
        KEYIMAGES_FIELD_NUMBER: _ClassVar[int]
        publicKey: _containers.RepeatedScalarFieldContainer[bytes]
        keyImages: _containers.RepeatedScalarFieldContainer[bytes]
        def __init__(self, publicKey: _Optional[_Iterable[bytes]] = ..., keyImages: _Optional[_Iterable[bytes]] = ...) -> None: ...
    MOBILECOINTXOIDENTIFICATION_FIELD_NUMBER: _ClassVar[int]
    mobileCoinTxoIdentification: PaymentMetaData.MobileCoinTxoIdentification
    def __init__(self, mobileCoinTxoIdentification: _Optional[_Union[PaymentMetaData.MobileCoinTxoIdentification, _Mapping]] = ...) -> None: ...
