# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: cds2.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\ncds2.proto\x12\x0forg.signal.cdsi\"\xae\x01\n\rClientRequest\x12\x15\n\raci_uak_pairs\x18\x01 \x01(\x0c\x12\x12\n\nprev_e164s\x18\x02 \x01(\x0c\x12\x11\n\tnew_e164s\x18\x03 \x01(\x0c\x12\x15\n\rdiscard_e164s\x18\x04 \x01(\x0c\x12\r\n\x05token\x18\x06 \x01(\x0c\x12\x11\n\ttoken_ack\x18\x07 \x01(\x08\x12 \n\x18return_acis_without_uaks\x18\x08 \x01(\x08J\x04\x08\x05\x10\x06\"_\n\x0e\x43lientResponse\x12\x1c\n\x14\x65\x31\x36\x34_pni_aci_triples\x18\x01 \x01(\x0c\x12\r\n\x05token\x18\x03 \x01(\x0c\x12\x1a\n\x12\x64\x65\x62ug_permits_used\x18\x04 \x01(\x05J\x04\x08\x02\x10\x03\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'cds2_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _globals['_CLIENTREQUEST']._serialized_start=32
  _globals['_CLIENTREQUEST']._serialized_end=206
  _globals['_CLIENTRESPONSE']._serialized_start=208
  _globals['_CLIENTRESPONSE']._serialized_end=303
# @@protoc_insertion_point(module_scope)
