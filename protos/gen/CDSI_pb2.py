# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: CDSI.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\nCDSI.proto\x12\x0forg.signal.cdsi\"\x9f\x01\n\rClientRequest\x12\x13\n\x0b\x61\x63iUakPairs\x18\x01 \x01(\x0c\x12\x11\n\tprevE164s\x18\x02 \x01(\x0c\x12\x10\n\x08newE164s\x18\x03 \x01(\x0c\x12\x14\n\x0c\x64iscardE164s\x18\x04 \x01(\x0c\x12\r\n\x05token\x18\x06 \x01(\x0c\x12\x10\n\x08tokenAck\x18\x07 \x01(\x08\x12\x1d\n\x15returnAcisWithoutUaks\x18\x08 \x01(\x08\"l\n\x0e\x43lientResponse\x12\x19\n\x11\x65\x31\x36\x34PniAciTriples\x18\x01 \x01(\x0c\x12\x16\n\x0eretryAfterSecs\x18\x02 \x01(\x05\x12\r\n\x05token\x18\x03 \x01(\x0c\x12\x18\n\x10\x64\x65\x62ugPermitsUsed\x18\x04 \x01(\x05\"W\n\x0b\x45nclaveLoad\x12\x10\n\x08\x63learAll\x18\x01 \x01(\x08\x12\x1b\n\x13\x65\x31\x36\x34\x41\x63iPniUakTuples\x18\x02 \x01(\x0c\x12\x19\n\x11sharedTokenSecret\x18\x03 \x01(\x0c\"U\n\x14\x43lientHandshakeStart\x12\x16\n\x0etestonlyPubkey\x18\x01 \x01(\x0c\x12\x10\n\x08\x65vidence\x18\x02 \x01(\x0c\x12\x13\n\x0b\x65ndorsement\x18\x03 \x01(\x0c\x42\x19\n\x15org.signal.cdsi.protoP\x01\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'CDSI_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\025org.signal.cdsi.protoP\001'
  _globals['_CLIENTREQUEST']._serialized_start=32
  _globals['_CLIENTREQUEST']._serialized_end=191
  _globals['_CLIENTRESPONSE']._serialized_start=193
  _globals['_CLIENTRESPONSE']._serialized_end=301
  _globals['_ENCLAVELOAD']._serialized_start=303
  _globals['_ENCLAVELOAD']._serialized_end=390
  _globals['_CLIENTHANDSHAKESTART']._serialized_start=392
  _globals['_CLIENTHANDSHAKESTART']._serialized_end=477
# @@protoc_insertion_point(module_scope)
