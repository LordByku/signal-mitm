from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class ASNPEvidence(_message.Message):
    __slots__ = ("attestation_data", "pcrs", "msg", "sig", "snp_report", "runtime_data", "akcert_der")
    ATTESTATION_DATA_FIELD_NUMBER: _ClassVar[int]
    PCRS_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    SIG_FIELD_NUMBER: _ClassVar[int]
    SNP_REPORT_FIELD_NUMBER: _ClassVar[int]
    RUNTIME_DATA_FIELD_NUMBER: _ClassVar[int]
    AKCERT_DER_FIELD_NUMBER: _ClassVar[int]
    attestation_data: bytes
    pcrs: bytes
    msg: bytes
    sig: bytes
    snp_report: bytes
    runtime_data: bytes
    akcert_der: bytes
    def __init__(self, attestation_data: _Optional[bytes] = ..., pcrs: _Optional[bytes] = ..., msg: _Optional[bytes] = ..., sig: _Optional[bytes] = ..., snp_report: _Optional[bytes] = ..., runtime_data: _Optional[bytes] = ..., akcert_der: _Optional[bytes] = ...) -> None: ...

class ASNPEndorsements(_message.Message):
    __slots__ = ("intermediate_der", "vcek_der", "ask_der")
    INTERMEDIATE_DER_FIELD_NUMBER: _ClassVar[int]
    VCEK_DER_FIELD_NUMBER: _ClassVar[int]
    ASK_DER_FIELD_NUMBER: _ClassVar[int]
    intermediate_der: bytes
    vcek_der: bytes
    ask_der: bytes
    def __init__(self, intermediate_der: _Optional[bytes] = ..., vcek_der: _Optional[bytes] = ..., ask_der: _Optional[bytes] = ...) -> None: ...
