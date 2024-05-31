# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: Groups.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0cGroups.proto\"\x8a\x01\n\x16\x41vatarUploadAttributes\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x12\n\ncredential\x18\x02 \x01(\t\x12\x0b\n\x03\x61\x63l\x18\x03 \x01(\t\x12\x11\n\talgorithm\x18\x04 \x01(\t\x12\x0c\n\x04\x64\x61te\x18\x05 \x01(\t\x12\x0e\n\x06policy\x18\x06 \x01(\t\x12\x11\n\tsignature\x18\x07 \x01(\t\"\xad\x01\n\x06Member\x12\x0e\n\x06userId\x18\x01 \x01(\x0c\x12\x1a\n\x04role\x18\x02 \x01(\x0e\x32\x0c.Member.Role\x12\x12\n\nprofileKey\x18\x03 \x01(\x0c\x12\x14\n\x0cpresentation\x18\x04 \x01(\x0c\x12\x18\n\x10joinedAtRevision\x18\x05 \x01(\r\"3\n\x04Role\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x0b\n\x07\x44\x45\x46\x41ULT\x10\x01\x12\x11\n\rADMINISTRATOR\x10\x02\"R\n\rPendingMember\x12\x17\n\x06member\x18\x01 \x01(\x0b\x32\x07.Member\x12\x15\n\raddedByUserId\x18\x02 \x01(\x0c\x12\x11\n\ttimestamp\x18\x03 \x01(\x04\"_\n\x10RequestingMember\x12\x0e\n\x06userId\x18\x01 \x01(\x0c\x12\x12\n\nprofileKey\x18\x02 \x01(\x0c\x12\x14\n\x0cpresentation\x18\x03 \x01(\x0c\x12\x11\n\ttimestamp\x18\x04 \x01(\x04\"1\n\x0c\x42\x61nnedMember\x12\x0e\n\x06userId\x18\x01 \x01(\x0c\x12\x11\n\ttimestamp\x18\x02 \x01(\x04\"\x86\x02\n\rAccessControl\x12\x31\n\nattributes\x18\x01 \x01(\x0e\x32\x1d.AccessControl.AccessRequired\x12.\n\x07members\x18\x02 \x01(\x0e\x32\x1d.AccessControl.AccessRequired\x12\x38\n\x11\x61\x64\x64\x46romInviteLink\x18\x03 \x01(\x0e\x32\x1d.AccessControl.AccessRequired\"X\n\x0e\x41\x63\x63\x65ssRequired\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x07\n\x03\x41NY\x10\x01\x12\n\n\x06MEMBER\x10\x02\x12\x11\n\rADMINISTRATOR\x10\x03\x12\x11\n\rUNSATISFIABLE\x10\x04\"\xf7\x02\n\x05Group\x12\x11\n\tpublicKey\x18\x01 \x01(\x0c\x12\r\n\x05title\x18\x02 \x01(\x0c\x12\x0e\n\x06\x61vatar\x18\x03 \x01(\t\x12!\n\x19\x64isappearingMessagesTimer\x18\x04 \x01(\x0c\x12%\n\raccessControl\x18\x05 \x01(\x0b\x32\x0e.AccessControl\x12\x10\n\x08revision\x18\x06 \x01(\r\x12\x18\n\x07members\x18\x07 \x03(\x0b\x32\x07.Member\x12&\n\x0ependingMembers\x18\x08 \x03(\x0b\x32\x0e.PendingMember\x12,\n\x11requestingMembers\x18\t \x03(\x0b\x32\x11.RequestingMember\x12\x1a\n\x12inviteLinkPassword\x18\n \x01(\x0c\x12\x13\n\x0b\x64\x65scription\x18\x0b \x01(\x0c\x12\x19\n\x11\x61nnouncementsOnly\x18\x0c \x01(\x08\x12$\n\rbannedMembers\x18\r \x03(\x0b\x32\r.BannedMember\"\xad\x1a\n\x0bGroupChange\x12\x0f\n\x07\x61\x63tions\x18\x01 \x01(\x0c\x12\x17\n\x0fserverSignature\x18\x02 \x01(\x0c\x12\x13\n\x0b\x63hangeEpoch\x18\x03 \x01(\r\x1a\xde\x19\n\x07\x41\x63tions\x12\x17\n\x0fsourceServiceId\x18\x01 \x01(\x0c\x12\x10\n\x08revision\x18\x02 \x01(\r\x12\x38\n\naddMembers\x18\x03 \x03(\x0b\x32$.GroupChange.Actions.AddMemberAction\x12>\n\rdeleteMembers\x18\x04 \x03(\x0b\x32\'.GroupChange.Actions.DeleteMemberAction\x12\x46\n\x11modifyMemberRoles\x18\x05 \x03(\x0b\x32+.GroupChange.Actions.ModifyMemberRoleAction\x12R\n\x17modifyMemberProfileKeys\x18\x06 \x03(\x0b\x32\x31.GroupChange.Actions.ModifyMemberProfileKeyAction\x12\x46\n\x11\x61\x64\x64PendingMembers\x18\x07 \x03(\x0b\x32+.GroupChange.Actions.AddPendingMemberAction\x12L\n\x14\x64\x65letePendingMembers\x18\x08 \x03(\x0b\x32..GroupChange.Actions.DeletePendingMemberAction\x12N\n\x15promotePendingMembers\x18\t \x03(\x0b\x32/.GroupChange.Actions.PromotePendingMemberAction\x12;\n\x0bmodifyTitle\x18\n \x01(\x0b\x32&.GroupChange.Actions.ModifyTitleAction\x12=\n\x0cmodifyAvatar\x18\x0b \x01(\x0b\x32\'.GroupChange.Actions.ModifyAvatarAction\x12\x63\n\x1fmodifyDisappearingMessagesTimer\x18\x0c \x01(\x0b\x32:.GroupChange.Actions.ModifyDisappearingMessagesTimerAction\x12X\n\x16modifyAttributesAccess\x18\r \x01(\x0b\x32\x38.GroupChange.Actions.ModifyAttributesAccessControlAction\x12Q\n\x12modifyMemberAccess\x18\x0e \x01(\x0b\x32\x35.GroupChange.Actions.ModifyMembersAccessControlAction\x12\x66\n\x1dmodifyAddFromInviteLinkAccess\x18\x0f \x01(\x0b\x32?.GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction\x12L\n\x14\x61\x64\x64RequestingMembers\x18\x10 \x03(\x0b\x32..GroupChange.Actions.AddRequestingMemberAction\x12R\n\x17\x64\x65leteRequestingMembers\x18\x11 \x03(\x0b\x32\x31.GroupChange.Actions.DeleteRequestingMemberAction\x12T\n\x18promoteRequestingMembers\x18\x12 \x03(\x0b\x32\x32.GroupChange.Actions.PromoteRequestingMemberAction\x12U\n\x18modifyInviteLinkPassword\x18\x13 \x01(\x0b\x32\x33.GroupChange.Actions.ModifyInviteLinkPasswordAction\x12G\n\x11modifyDescription\x18\x14 \x01(\x0b\x32,.GroupChange.Actions.ModifyDescriptionAction\x12S\n\x17modifyAnnouncementsOnly\x18\x15 \x01(\x0b\x32\x32.GroupChange.Actions.ModifyAnnouncementsOnlyAction\x12\x44\n\x10\x61\x64\x64\x42\x61nnedMembers\x18\x16 \x03(\x0b\x32*.GroupChange.Actions.AddBannedMemberAction\x12J\n\x13\x64\x65leteBannedMembers\x18\x17 \x03(\x0b\x32-.GroupChange.Actions.DeleteBannedMemberAction\x12\x64\n\x1bpromotePendingPniAciMembers\x18\x18 \x03(\x0b\x32?.GroupChange.Actions.PromotePendingPniAciMemberProfileKeyAction\x1a\x45\n\x0f\x41\x64\x64MemberAction\x12\x16\n\x05\x61\x64\x64\x65\x64\x18\x01 \x01(\x0b\x32\x07.Member\x12\x1a\n\x12joinFromInviteLink\x18\x02 \x01(\x08\x1a+\n\x12\x44\x65leteMemberAction\x12\x15\n\rdeletedUserId\x18\x01 \x01(\x0c\x1a\x44\n\x16ModifyMemberRoleAction\x12\x0e\n\x06userId\x18\x01 \x01(\x0c\x12\x1a\n\x04role\x18\x02 \x01(\x0e\x32\x0c.Member.Role\x1aZ\n\x1cModifyMemberProfileKeyAction\x12\x14\n\x0cpresentation\x18\x01 \x01(\x0c\x12\x0f\n\x07user_id\x18\x02 \x01(\x0c\x12\x13\n\x0bprofile_key\x18\x03 \x01(\x0c\x1a\x37\n\x16\x41\x64\x64PendingMemberAction\x12\x1d\n\x05\x61\x64\x64\x65\x64\x18\x01 \x01(\x0b\x32\x0e.PendingMember\x1a\x32\n\x19\x44\x65letePendingMemberAction\x12\x15\n\rdeletedUserId\x18\x01 \x01(\x0c\x1aX\n\x1aPromotePendingMemberAction\x12\x14\n\x0cpresentation\x18\x01 \x01(\x0c\x12\x0f\n\x07user_id\x18\x02 \x01(\x0c\x12\x13\n\x0bprofile_key\x18\x03 \x01(\x0c\x1as\n*PromotePendingPniAciMemberProfileKeyAction\x12\x14\n\x0cpresentation\x18\x01 \x01(\x0c\x12\x0e\n\x06userId\x18\x02 \x01(\x0c\x12\x0b\n\x03pni\x18\x03 \x01(\x0c\x12\x12\n\nprofileKey\x18\x04 \x01(\x0c\x1a=\n\x19\x41\x64\x64RequestingMemberAction\x12 \n\x05\x61\x64\x64\x65\x64\x18\x01 \x01(\x0b\x32\x11.RequestingMember\x1a\x35\n\x1c\x44\x65leteRequestingMemberAction\x12\x15\n\rdeletedUserId\x18\x01 \x01(\x0c\x1aK\n\x1dPromoteRequestingMemberAction\x12\x0e\n\x06userId\x18\x01 \x01(\x0c\x12\x1a\n\x04role\x18\x02 \x01(\x0e\x32\x0c.Member.Role\x1a\x35\n\x15\x41\x64\x64\x42\x61nnedMemberAction\x12\x1c\n\x05\x61\x64\x64\x65\x64\x18\x01 \x01(\x0b\x32\r.BannedMember\x1a\x31\n\x18\x44\x65leteBannedMemberAction\x12\x15\n\rdeletedUserId\x18\x01 \x01(\x0c\x1a\"\n\x11ModifyTitleAction\x12\r\n\x05title\x18\x01 \x01(\x0c\x1a.\n\x17ModifyDescriptionAction\x12\x13\n\x0b\x64\x65scription\x18\x01 \x01(\x0c\x1a$\n\x12ModifyAvatarAction\x12\x0e\n\x06\x61vatar\x18\x01 \x01(\t\x1a\x36\n%ModifyDisappearingMessagesTimerAction\x12\r\n\x05timer\x18\x01 \x01(\x0c\x1a^\n#ModifyAttributesAccessControlAction\x12\x37\n\x10\x61ttributesAccess\x18\x01 \x01(\x0e\x32\x1d.AccessControl.AccessRequired\x1aX\n ModifyMembersAccessControlAction\x12\x34\n\rmembersAccess\x18\x01 \x01(\x0e\x32\x1d.AccessControl.AccessRequired\x1al\n*ModifyAddFromInviteLinkAccessControlAction\x12>\n\x17\x61\x64\x64\x46romInviteLinkAccess\x18\x01 \x01(\x0e\x32\x1d.AccessControl.AccessRequired\x1a<\n\x1eModifyInviteLinkPasswordAction\x12\x1a\n\x12inviteLinkPassword\x18\x01 \x01(\x0c\x1a:\n\x1dModifyAnnouncementsOnlyAction\x12\x19\n\x11\x61nnouncementsOnly\x18\x01 \x01(\x08\"\x97\x01\n\x0cGroupChanges\x12\x34\n\x0cgroupChanges\x18\x01 \x03(\x0b\x32\x1e.GroupChanges.GroupChangeState\x1aQ\n\x10GroupChangeState\x12!\n\x0bgroupChange\x18\x01 \x01(\x0b\x32\x0c.GroupChange\x12\x1a\n\ngroupState\x18\x02 \x01(\x0b\x32\x06.Group\"\x81\x01\n\x12GroupAttributeBlob\x12\x0f\n\x05title\x18\x01 \x01(\tH\x00\x12\x10\n\x06\x61vatar\x18\x02 \x01(\x0cH\x00\x12&\n\x1c\x64isappearingMessagesDuration\x18\x03 \x01(\rH\x00\x12\x15\n\x0b\x64\x65scription\x18\x04 \x01(\tH\x00\x42\t\n\x07\x63ontent\"\xb0\x01\n\x0fGroupInviteLink\x12@\n\nv1Contents\x18\x01 \x01(\x0b\x32*.GroupInviteLink.GroupInviteLinkContentsV1H\x00\x1aO\n\x19GroupInviteLinkContentsV1\x12\x16\n\x0egroupMasterKey\x18\x01 \x01(\x0c\x12\x1a\n\x12inviteLinkPassword\x18\x02 \x01(\x0c\x42\n\n\x08\x63ontents\"\xd5\x01\n\rGroupJoinInfo\x12\x11\n\tpublicKey\x18\x01 \x01(\x0c\x12\r\n\x05title\x18\x02 \x01(\x0c\x12\x0e\n\x06\x61vatar\x18\x03 \x01(\t\x12\x13\n\x0bmemberCount\x18\x04 \x01(\r\x12\x38\n\x11\x61\x64\x64\x46romInviteLink\x18\x05 \x01(\x0e\x32\x1d.AccessControl.AccessRequired\x12\x10\n\x08revision\x18\x06 \x01(\r\x12\x1c\n\x14pendingAdminApproval\x18\x07 \x01(\x08\x12\x13\n\x0b\x64\x65scription\x18\x08 \x01(\x0c\"(\n\x17GroupExternalCredential\x12\r\n\x05token\x18\x01 \x01(\tB+\n\'org.signal.storageservice.protos.groupsP\x01\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'Groups_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\'org.signal.storageservice.protos.groupsP\001'
  _globals['_AVATARUPLOADATTRIBUTES']._serialized_start=17
  _globals['_AVATARUPLOADATTRIBUTES']._serialized_end=155
  _globals['_MEMBER']._serialized_start=158
  _globals['_MEMBER']._serialized_end=331
  _globals['_MEMBER_ROLE']._serialized_start=280
  _globals['_MEMBER_ROLE']._serialized_end=331
  _globals['_PENDINGMEMBER']._serialized_start=333
  _globals['_PENDINGMEMBER']._serialized_end=415
  _globals['_REQUESTINGMEMBER']._serialized_start=417
  _globals['_REQUESTINGMEMBER']._serialized_end=512
  _globals['_BANNEDMEMBER']._serialized_start=514
  _globals['_BANNEDMEMBER']._serialized_end=563
  _globals['_ACCESSCONTROL']._serialized_start=566
  _globals['_ACCESSCONTROL']._serialized_end=828
  _globals['_ACCESSCONTROL_ACCESSREQUIRED']._serialized_start=740
  _globals['_ACCESSCONTROL_ACCESSREQUIRED']._serialized_end=828
  _globals['_GROUP']._serialized_start=831
  _globals['_GROUP']._serialized_end=1206
  _globals['_GROUPCHANGE']._serialized_start=1209
  _globals['_GROUPCHANGE']._serialized_end=4582
  _globals['_GROUPCHANGE_ACTIONS']._serialized_start=1288
  _globals['_GROUPCHANGE_ACTIONS']._serialized_end=4582
  _globals['_GROUPCHANGE_ACTIONS_ADDMEMBERACTION']._serialized_start=3093
  _globals['_GROUPCHANGE_ACTIONS_ADDMEMBERACTION']._serialized_end=3162
  _globals['_GROUPCHANGE_ACTIONS_DELETEMEMBERACTION']._serialized_start=3164
  _globals['_GROUPCHANGE_ACTIONS_DELETEMEMBERACTION']._serialized_end=3207
  _globals['_GROUPCHANGE_ACTIONS_MODIFYMEMBERROLEACTION']._serialized_start=3209
  _globals['_GROUPCHANGE_ACTIONS_MODIFYMEMBERROLEACTION']._serialized_end=3277
  _globals['_GROUPCHANGE_ACTIONS_MODIFYMEMBERPROFILEKEYACTION']._serialized_start=3279
  _globals['_GROUPCHANGE_ACTIONS_MODIFYMEMBERPROFILEKEYACTION']._serialized_end=3369
  _globals['_GROUPCHANGE_ACTIONS_ADDPENDINGMEMBERACTION']._serialized_start=3371
  _globals['_GROUPCHANGE_ACTIONS_ADDPENDINGMEMBERACTION']._serialized_end=3426
  _globals['_GROUPCHANGE_ACTIONS_DELETEPENDINGMEMBERACTION']._serialized_start=3428
  _globals['_GROUPCHANGE_ACTIONS_DELETEPENDINGMEMBERACTION']._serialized_end=3478
  _globals['_GROUPCHANGE_ACTIONS_PROMOTEPENDINGMEMBERACTION']._serialized_start=3480
  _globals['_GROUPCHANGE_ACTIONS_PROMOTEPENDINGMEMBERACTION']._serialized_end=3568
  _globals['_GROUPCHANGE_ACTIONS_PROMOTEPENDINGPNIACIMEMBERPROFILEKEYACTION']._serialized_start=3570
  _globals['_GROUPCHANGE_ACTIONS_PROMOTEPENDINGPNIACIMEMBERPROFILEKEYACTION']._serialized_end=3685
  _globals['_GROUPCHANGE_ACTIONS_ADDREQUESTINGMEMBERACTION']._serialized_start=3687
  _globals['_GROUPCHANGE_ACTIONS_ADDREQUESTINGMEMBERACTION']._serialized_end=3748
  _globals['_GROUPCHANGE_ACTIONS_DELETEREQUESTINGMEMBERACTION']._serialized_start=3750
  _globals['_GROUPCHANGE_ACTIONS_DELETEREQUESTINGMEMBERACTION']._serialized_end=3803
  _globals['_GROUPCHANGE_ACTIONS_PROMOTEREQUESTINGMEMBERACTION']._serialized_start=3805
  _globals['_GROUPCHANGE_ACTIONS_PROMOTEREQUESTINGMEMBERACTION']._serialized_end=3880
  _globals['_GROUPCHANGE_ACTIONS_ADDBANNEDMEMBERACTION']._serialized_start=3882
  _globals['_GROUPCHANGE_ACTIONS_ADDBANNEDMEMBERACTION']._serialized_end=3935
  _globals['_GROUPCHANGE_ACTIONS_DELETEBANNEDMEMBERACTION']._serialized_start=3937
  _globals['_GROUPCHANGE_ACTIONS_DELETEBANNEDMEMBERACTION']._serialized_end=3986
  _globals['_GROUPCHANGE_ACTIONS_MODIFYTITLEACTION']._serialized_start=3988
  _globals['_GROUPCHANGE_ACTIONS_MODIFYTITLEACTION']._serialized_end=4022
  _globals['_GROUPCHANGE_ACTIONS_MODIFYDESCRIPTIONACTION']._serialized_start=4024
  _globals['_GROUPCHANGE_ACTIONS_MODIFYDESCRIPTIONACTION']._serialized_end=4070
  _globals['_GROUPCHANGE_ACTIONS_MODIFYAVATARACTION']._serialized_start=4072
  _globals['_GROUPCHANGE_ACTIONS_MODIFYAVATARACTION']._serialized_end=4108
  _globals['_GROUPCHANGE_ACTIONS_MODIFYDISAPPEARINGMESSAGESTIMERACTION']._serialized_start=4110
  _globals['_GROUPCHANGE_ACTIONS_MODIFYDISAPPEARINGMESSAGESTIMERACTION']._serialized_end=4164
  _globals['_GROUPCHANGE_ACTIONS_MODIFYATTRIBUTESACCESSCONTROLACTION']._serialized_start=4166
  _globals['_GROUPCHANGE_ACTIONS_MODIFYATTRIBUTESACCESSCONTROLACTION']._serialized_end=4260
  _globals['_GROUPCHANGE_ACTIONS_MODIFYMEMBERSACCESSCONTROLACTION']._serialized_start=4262
  _globals['_GROUPCHANGE_ACTIONS_MODIFYMEMBERSACCESSCONTROLACTION']._serialized_end=4350
  _globals['_GROUPCHANGE_ACTIONS_MODIFYADDFROMINVITELINKACCESSCONTROLACTION']._serialized_start=4352
  _globals['_GROUPCHANGE_ACTIONS_MODIFYADDFROMINVITELINKACCESSCONTROLACTION']._serialized_end=4460
  _globals['_GROUPCHANGE_ACTIONS_MODIFYINVITELINKPASSWORDACTION']._serialized_start=4462
  _globals['_GROUPCHANGE_ACTIONS_MODIFYINVITELINKPASSWORDACTION']._serialized_end=4522
  _globals['_GROUPCHANGE_ACTIONS_MODIFYANNOUNCEMENTSONLYACTION']._serialized_start=4524
  _globals['_GROUPCHANGE_ACTIONS_MODIFYANNOUNCEMENTSONLYACTION']._serialized_end=4582
  _globals['_GROUPCHANGES']._serialized_start=4585
  _globals['_GROUPCHANGES']._serialized_end=4736
  _globals['_GROUPCHANGES_GROUPCHANGESTATE']._serialized_start=4655
  _globals['_GROUPCHANGES_GROUPCHANGESTATE']._serialized_end=4736
  _globals['_GROUPATTRIBUTEBLOB']._serialized_start=4739
  _globals['_GROUPATTRIBUTEBLOB']._serialized_end=4868
  _globals['_GROUPINVITELINK']._serialized_start=4871
  _globals['_GROUPINVITELINK']._serialized_end=5047
  _globals['_GROUPINVITELINK_GROUPINVITELINKCONTENTSV1']._serialized_start=4956
  _globals['_GROUPINVITELINK_GROUPINVITELINKCONTENTSV1']._serialized_end=5035
  _globals['_GROUPJOININFO']._serialized_start=5050
  _globals['_GROUPJOININFO']._serialized_end=5263
  _globals['_GROUPEXTERNALCREDENTIAL']._serialized_start=5265
  _globals['_GROUPEXTERNALCREDENTIAL']._serialized_end=5305
# @@protoc_insertion_point(module_scope)
