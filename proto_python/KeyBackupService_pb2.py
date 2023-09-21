# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: KeyBackupService.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x16KeyBackupService.proto\x12\ntextsecure\"\x8c\x01\n\x07Request\x12)\n\x06\x62\x61\x63kup\x18\x01 \x01(\x0b\x32\x19.textsecure.BackupRequest\x12+\n\x07restore\x18\x02 \x01(\x0b\x32\x1a.textsecure.RestoreRequest\x12)\n\x06\x64\x65lete\x18\x03 \x01(\x0b\x32\x19.textsecure.DeleteRequest\"\x90\x01\n\x08Response\x12*\n\x06\x62\x61\x63kup\x18\x01 \x01(\x0b\x32\x1a.textsecure.BackupResponse\x12,\n\x07restore\x18\x02 \x01(\x0b\x32\x1b.textsecure.RestoreResponse\x12*\n\x06\x64\x65lete\x18\x03 \x01(\x0b\x32\x1a.textsecure.DeleteResponse\"\x83\x01\n\rBackupRequest\x12\x12\n\nservice_id\x18\x01 \x01(\x0c\x12\x11\n\tbackup_id\x18\x02 \x01(\x0c\x12\r\n\x05token\x18\x03 \x01(\x0c\x12\x12\n\nvalid_from\x18\x04 \x01(\x04\x12\x0c\n\x04\x64\x61ta\x18\x05 \x01(\x0c\x12\x0b\n\x03pin\x18\x06 \x01(\x0c\x12\r\n\x05tries\x18\x07 \x01(\r\"\x8b\x01\n\x0e\x42\x61\x63kupResponse\x12\x31\n\x06status\x18\x01 \x01(\x0e\x32!.textsecure.BackupResponse.Status\x12\r\n\x05token\x18\x02 \x01(\x0c\"7\n\x06Status\x12\x06\n\x02OK\x10\x01\x12\x12\n\x0e\x41LREADY_EXISTS\x10\x02\x12\x11\n\rNOT_YET_VALID\x10\x03\"g\n\x0eRestoreRequest\x12\x12\n\nservice_id\x18\x01 \x01(\x0c\x12\x11\n\tbackup_id\x18\x02 \x01(\x0c\x12\r\n\x05token\x18\x03 \x01(\x0c\x12\x12\n\nvalid_from\x18\x04 \x01(\x04\x12\x0b\n\x03pin\x18\x05 \x01(\x0c\"\xc9\x01\n\x0fRestoreResponse\x12\x32\n\x06status\x18\x01 \x01(\x0e\x32\".textsecure.RestoreResponse.Status\x12\r\n\x05token\x18\x02 \x01(\x0c\x12\x0c\n\x04\x64\x61ta\x18\x03 \x01(\x0c\x12\r\n\x05tries\x18\x04 \x01(\r\"V\n\x06Status\x12\x06\n\x02OK\x10\x01\x12\x12\n\x0eTOKEN_MISMATCH\x10\x02\x12\x11\n\rNOT_YET_VALID\x10\x03\x12\x0b\n\x07MISSING\x10\x04\x12\x10\n\x0cPIN_MISMATCH\x10\x05\"6\n\rDeleteRequest\x12\x12\n\nservice_id\x18\x01 \x01(\x0c\x12\x11\n\tbackup_id\x18\x02 \x01(\x0c\"\x10\n\x0e\x44\x65leteResponseB>\n:org.whispersystems.signalservice.internal.keybackup.protosP\x01')



_REQUEST = DESCRIPTOR.message_types_by_name['Request']
_RESPONSE = DESCRIPTOR.message_types_by_name['Response']
_BACKUPREQUEST = DESCRIPTOR.message_types_by_name['BackupRequest']
_BACKUPRESPONSE = DESCRIPTOR.message_types_by_name['BackupResponse']
_RESTOREREQUEST = DESCRIPTOR.message_types_by_name['RestoreRequest']
_RESTORERESPONSE = DESCRIPTOR.message_types_by_name['RestoreResponse']
_DELETEREQUEST = DESCRIPTOR.message_types_by_name['DeleteRequest']
_DELETERESPONSE = DESCRIPTOR.message_types_by_name['DeleteResponse']
_BACKUPRESPONSE_STATUS = _BACKUPRESPONSE.enum_types_by_name['Status']
_RESTORERESPONSE_STATUS = _RESTORERESPONSE.enum_types_by_name['Status']
Request = _reflection.GeneratedProtocolMessageType('Request', (_message.Message,), {
  'DESCRIPTOR' : _REQUEST,
  '__module__' : 'KeyBackupService_pb2'
  # @@protoc_insertion_point(class_scope:textsecure.Request)
  })
_sym_db.RegisterMessage(Request)

Response = _reflection.GeneratedProtocolMessageType('Response', (_message.Message,), {
  'DESCRIPTOR' : _RESPONSE,
  '__module__' : 'KeyBackupService_pb2'
  # @@protoc_insertion_point(class_scope:textsecure.Response)
  })
_sym_db.RegisterMessage(Response)

BackupRequest = _reflection.GeneratedProtocolMessageType('BackupRequest', (_message.Message,), {
  'DESCRIPTOR' : _BACKUPREQUEST,
  '__module__' : 'KeyBackupService_pb2'
  # @@protoc_insertion_point(class_scope:textsecure.BackupRequest)
  })
_sym_db.RegisterMessage(BackupRequest)

BackupResponse = _reflection.GeneratedProtocolMessageType('BackupResponse', (_message.Message,), {
  'DESCRIPTOR' : _BACKUPRESPONSE,
  '__module__' : 'KeyBackupService_pb2'
  # @@protoc_insertion_point(class_scope:textsecure.BackupResponse)
  })
_sym_db.RegisterMessage(BackupResponse)

RestoreRequest = _reflection.GeneratedProtocolMessageType('RestoreRequest', (_message.Message,), {
  'DESCRIPTOR' : _RESTOREREQUEST,
  '__module__' : 'KeyBackupService_pb2'
  # @@protoc_insertion_point(class_scope:textsecure.RestoreRequest)
  })
_sym_db.RegisterMessage(RestoreRequest)

RestoreResponse = _reflection.GeneratedProtocolMessageType('RestoreResponse', (_message.Message,), {
  'DESCRIPTOR' : _RESTORERESPONSE,
  '__module__' : 'KeyBackupService_pb2'
  # @@protoc_insertion_point(class_scope:textsecure.RestoreResponse)
  })
_sym_db.RegisterMessage(RestoreResponse)

DeleteRequest = _reflection.GeneratedProtocolMessageType('DeleteRequest', (_message.Message,), {
  'DESCRIPTOR' : _DELETEREQUEST,
  '__module__' : 'KeyBackupService_pb2'
  # @@protoc_insertion_point(class_scope:textsecure.DeleteRequest)
  })
_sym_db.RegisterMessage(DeleteRequest)

DeleteResponse = _reflection.GeneratedProtocolMessageType('DeleteResponse', (_message.Message,), {
  'DESCRIPTOR' : _DELETERESPONSE,
  '__module__' : 'KeyBackupService_pb2'
  # @@protoc_insertion_point(class_scope:textsecure.DeleteResponse)
  })
_sym_db.RegisterMessage(DeleteResponse)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n:org.whispersystems.signalservice.internal.keybackup.protosP\001'
  _REQUEST._serialized_start=39
  _REQUEST._serialized_end=179
  _RESPONSE._serialized_start=182
  _RESPONSE._serialized_end=326
  _BACKUPREQUEST._serialized_start=329
  _BACKUPREQUEST._serialized_end=460
  _BACKUPRESPONSE._serialized_start=463
  _BACKUPRESPONSE._serialized_end=602
  _BACKUPRESPONSE_STATUS._serialized_start=547
  _BACKUPRESPONSE_STATUS._serialized_end=602
  _RESTOREREQUEST._serialized_start=604
  _RESTOREREQUEST._serialized_end=707
  _RESTORERESPONSE._serialized_start=710
  _RESTORERESPONSE._serialized_end=911
  _RESTORERESPONSE_STATUS._serialized_start=825
  _RESTORERESPONSE_STATUS._serialized_end=911
  _DELETEREQUEST._serialized_start=913
  _DELETEREQUEST._serialized_end=967
  _DELETERESPONSE._serialized_start=969
  _DELETERESPONSE._serialized_end=985
# @@protoc_insertion_point(module_scope)