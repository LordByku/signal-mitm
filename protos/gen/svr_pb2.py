# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: svr.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tsvr.proto\x12\x0eorg.signal.svr\"C\n\x14\x43lientHandshakeStart\x12\x10\n\x08\x65vidence\x18\x02 \x01(\x0c\x12\x13\n\x0b\x65ndorsement\x18\x03 \x01(\x0cJ\x04\x08\x01\x10\x02\"u\n\x0fRaftGroupConfig\x12\x10\n\x08group_id\x18\x01 \x01(\x06\x12\x1b\n\x13min_voting_replicas\x18\x02 \x01(\r\x12\x1b\n\x13max_voting_replicas\x18\x03 \x01(\r\x12\x16\n\x0esuper_majority\x18\x04 \x01(\r\"\\\n\x0f\x41ttestationData\x12\x12\n\npublic_key\x18\x01 \x01(\x0c\x12\x35\n\x0cgroup_config\x18\x02 \x01(\x0b\x32\x1f.org.signal.svr.RaftGroupConfigb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'svr_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _globals['_CLIENTHANDSHAKESTART']._serialized_start=29
  _globals['_CLIENTHANDSHAKESTART']._serialized_end=96
  _globals['_RAFTGROUPCONFIG']._serialized_start=98
  _globals['_RAFTGROUPCONFIG']._serialized_end=215
  _globals['_ATTESTATIONDATA']._serialized_start=217
  _globals['_ATTESTATIONDATA']._serialized_end=309
# @@protoc_insertion_point(module_scope)
