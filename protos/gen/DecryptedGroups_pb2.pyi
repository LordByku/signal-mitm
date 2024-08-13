import Groups_pb2 as _Groups_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnabledState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN: _ClassVar[EnabledState]
    ENABLED: _ClassVar[EnabledState]
    DISABLED: _ClassVar[EnabledState]
UNKNOWN: EnabledState
ENABLED: EnabledState
DISABLED: EnabledState

class DecryptedMember(_message.Message):
    __slots__ = ("aciBytes", "role", "profileKey", "joinedAtRevision", "pniBytes")
    ACIBYTES_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    JOINEDATREVISION_FIELD_NUMBER: _ClassVar[int]
    PNIBYTES_FIELD_NUMBER: _ClassVar[int]
    aciBytes: bytes
    role: _Groups_pb2.Member.Role
    profileKey: bytes
    joinedAtRevision: int
    pniBytes: bytes
    def __init__(self, aciBytes: _Optional[bytes] = ..., role: _Optional[_Union[_Groups_pb2.Member.Role, str]] = ..., profileKey: _Optional[bytes] = ..., joinedAtRevision: _Optional[int] = ..., pniBytes: _Optional[bytes] = ...) -> None: ...

class DecryptedPendingMember(_message.Message):
    __slots__ = ("serviceIdBytes", "role", "addedByAci", "timestamp", "serviceIdCipherText")
    SERVICEIDBYTES_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    ADDEDBYACI_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SERVICEIDCIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    serviceIdBytes: bytes
    role: _Groups_pb2.Member.Role
    addedByAci: bytes
    timestamp: int
    serviceIdCipherText: bytes
    def __init__(self, serviceIdBytes: _Optional[bytes] = ..., role: _Optional[_Union[_Groups_pb2.Member.Role, str]] = ..., addedByAci: _Optional[bytes] = ..., timestamp: _Optional[int] = ..., serviceIdCipherText: _Optional[bytes] = ...) -> None: ...

class DecryptedRequestingMember(_message.Message):
    __slots__ = ("aciBytes", "profileKey", "timestamp")
    ACIBYTES_FIELD_NUMBER: _ClassVar[int]
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    aciBytes: bytes
    profileKey: bytes
    timestamp: int
    def __init__(self, aciBytes: _Optional[bytes] = ..., profileKey: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...

class DecryptedBannedMember(_message.Message):
    __slots__ = ("serviceIdBytes", "timestamp")
    SERVICEIDBYTES_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    serviceIdBytes: bytes
    timestamp: int
    def __init__(self, serviceIdBytes: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...

class DecryptedPendingMemberRemoval(_message.Message):
    __slots__ = ("serviceIdBytes", "serviceIdCipherText")
    SERVICEIDBYTES_FIELD_NUMBER: _ClassVar[int]
    SERVICEIDCIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    serviceIdBytes: bytes
    serviceIdCipherText: bytes
    def __init__(self, serviceIdBytes: _Optional[bytes] = ..., serviceIdCipherText: _Optional[bytes] = ...) -> None: ...

class DecryptedApproveMember(_message.Message):
    __slots__ = ("aciBytes", "role")
    ACIBYTES_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    aciBytes: bytes
    role: _Groups_pb2.Member.Role
    def __init__(self, aciBytes: _Optional[bytes] = ..., role: _Optional[_Union[_Groups_pb2.Member.Role, str]] = ...) -> None: ...

class DecryptedModifyMemberRole(_message.Message):
    __slots__ = ("aciBytes", "role")
    ACIBYTES_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    aciBytes: bytes
    role: _Groups_pb2.Member.Role
    def __init__(self, aciBytes: _Optional[bytes] = ..., role: _Optional[_Union[_Groups_pb2.Member.Role, str]] = ...) -> None: ...

class DecryptedGroup(_message.Message):
    __slots__ = ("title", "avatar", "disappearingMessagesTimer", "accessControl", "revision", "members", "pendingMembers", "requestingMembers", "inviteLinkPassword", "description", "isAnnouncementGroup", "bannedMembers")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    DISAPPEARINGMESSAGESTIMER_FIELD_NUMBER: _ClassVar[int]
    ACCESSCONTROL_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    PENDINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
    REQUESTINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
    INVITELINKPASSWORD_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ISANNOUNCEMENTGROUP_FIELD_NUMBER: _ClassVar[int]
    BANNEDMEMBERS_FIELD_NUMBER: _ClassVar[int]
    title: str
    avatar: str
    disappearingMessagesTimer: DecryptedTimer
    accessControl: _Groups_pb2.AccessControl
    revision: int
    members: _containers.RepeatedCompositeFieldContainer[DecryptedMember]
    pendingMembers: _containers.RepeatedCompositeFieldContainer[DecryptedPendingMember]
    requestingMembers: _containers.RepeatedCompositeFieldContainer[DecryptedRequestingMember]
    inviteLinkPassword: bytes
    description: str
    isAnnouncementGroup: EnabledState
    bannedMembers: _containers.RepeatedCompositeFieldContainer[DecryptedBannedMember]
    def __init__(self, title: _Optional[str] = ..., avatar: _Optional[str] = ..., disappearingMessagesTimer: _Optional[_Union[DecryptedTimer, _Mapping]] = ..., accessControl: _Optional[_Union[_Groups_pb2.AccessControl, _Mapping]] = ..., revision: _Optional[int] = ..., members: _Optional[_Iterable[_Union[DecryptedMember, _Mapping]]] = ..., pendingMembers: _Optional[_Iterable[_Union[DecryptedPendingMember, _Mapping]]] = ..., requestingMembers: _Optional[_Iterable[_Union[DecryptedRequestingMember, _Mapping]]] = ..., inviteLinkPassword: _Optional[bytes] = ..., description: _Optional[str] = ..., isAnnouncementGroup: _Optional[_Union[EnabledState, str]] = ..., bannedMembers: _Optional[_Iterable[_Union[DecryptedBannedMember, _Mapping]]] = ...) -> None: ...

class DecryptedGroupChange(_message.Message):
    __slots__ = ("editorServiceIdBytes", "revision", "newMembers", "deleteMembers", "modifyMemberRoles", "modifiedProfileKeys", "newPendingMembers", "deletePendingMembers", "promotePendingMembers", "newTitle", "newAvatar", "newTimer", "newAttributeAccess", "newMemberAccess", "newInviteLinkAccess", "newRequestingMembers", "deleteRequestingMembers", "promoteRequestingMembers", "newInviteLinkPassword", "newDescription", "newIsAnnouncementGroup", "newBannedMembers", "deleteBannedMembers", "promotePendingPniAciMembers")
    EDITORSERVICEIDBYTES_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    NEWMEMBERS_FIELD_NUMBER: _ClassVar[int]
    DELETEMEMBERS_FIELD_NUMBER: _ClassVar[int]
    MODIFYMEMBERROLES_FIELD_NUMBER: _ClassVar[int]
    MODIFIEDPROFILEKEYS_FIELD_NUMBER: _ClassVar[int]
    NEWPENDINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
    DELETEPENDINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
    PROMOTEPENDINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
    NEWTITLE_FIELD_NUMBER: _ClassVar[int]
    NEWAVATAR_FIELD_NUMBER: _ClassVar[int]
    NEWTIMER_FIELD_NUMBER: _ClassVar[int]
    NEWATTRIBUTEACCESS_FIELD_NUMBER: _ClassVar[int]
    NEWMEMBERACCESS_FIELD_NUMBER: _ClassVar[int]
    NEWINVITELINKACCESS_FIELD_NUMBER: _ClassVar[int]
    NEWREQUESTINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
    DELETEREQUESTINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
    PROMOTEREQUESTINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
    NEWINVITELINKPASSWORD_FIELD_NUMBER: _ClassVar[int]
    NEWDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    NEWISANNOUNCEMENTGROUP_FIELD_NUMBER: _ClassVar[int]
    NEWBANNEDMEMBERS_FIELD_NUMBER: _ClassVar[int]
    DELETEBANNEDMEMBERS_FIELD_NUMBER: _ClassVar[int]
    PROMOTEPENDINGPNIACIMEMBERS_FIELD_NUMBER: _ClassVar[int]
    editorServiceIdBytes: bytes
    revision: int
    newMembers: _containers.RepeatedCompositeFieldContainer[DecryptedMember]
    deleteMembers: _containers.RepeatedScalarFieldContainer[bytes]
    modifyMemberRoles: _containers.RepeatedCompositeFieldContainer[DecryptedModifyMemberRole]
    modifiedProfileKeys: _containers.RepeatedCompositeFieldContainer[DecryptedMember]
    newPendingMembers: _containers.RepeatedCompositeFieldContainer[DecryptedPendingMember]
    deletePendingMembers: _containers.RepeatedCompositeFieldContainer[DecryptedPendingMemberRemoval]
    promotePendingMembers: _containers.RepeatedCompositeFieldContainer[DecryptedMember]
    newTitle: DecryptedString
    newAvatar: DecryptedString
    newTimer: DecryptedTimer
    newAttributeAccess: _Groups_pb2.AccessControl.AccessRequired
    newMemberAccess: _Groups_pb2.AccessControl.AccessRequired
    newInviteLinkAccess: _Groups_pb2.AccessControl.AccessRequired
    newRequestingMembers: _containers.RepeatedCompositeFieldContainer[DecryptedRequestingMember]
    deleteRequestingMembers: _containers.RepeatedScalarFieldContainer[bytes]
    promoteRequestingMembers: _containers.RepeatedCompositeFieldContainer[DecryptedApproveMember]
    newInviteLinkPassword: bytes
    newDescription: DecryptedString
    newIsAnnouncementGroup: EnabledState
    newBannedMembers: _containers.RepeatedCompositeFieldContainer[DecryptedBannedMember]
    deleteBannedMembers: _containers.RepeatedCompositeFieldContainer[DecryptedBannedMember]
    promotePendingPniAciMembers: _containers.RepeatedCompositeFieldContainer[DecryptedMember]
    def __init__(self, editorServiceIdBytes: _Optional[bytes] = ..., revision: _Optional[int] = ..., newMembers: _Optional[_Iterable[_Union[DecryptedMember, _Mapping]]] = ..., deleteMembers: _Optional[_Iterable[bytes]] = ..., modifyMemberRoles: _Optional[_Iterable[_Union[DecryptedModifyMemberRole, _Mapping]]] = ..., modifiedProfileKeys: _Optional[_Iterable[_Union[DecryptedMember, _Mapping]]] = ..., newPendingMembers: _Optional[_Iterable[_Union[DecryptedPendingMember, _Mapping]]] = ..., deletePendingMembers: _Optional[_Iterable[_Union[DecryptedPendingMemberRemoval, _Mapping]]] = ..., promotePendingMembers: _Optional[_Iterable[_Union[DecryptedMember, _Mapping]]] = ..., newTitle: _Optional[_Union[DecryptedString, _Mapping]] = ..., newAvatar: _Optional[_Union[DecryptedString, _Mapping]] = ..., newTimer: _Optional[_Union[DecryptedTimer, _Mapping]] = ..., newAttributeAccess: _Optional[_Union[_Groups_pb2.AccessControl.AccessRequired, str]] = ..., newMemberAccess: _Optional[_Union[_Groups_pb2.AccessControl.AccessRequired, str]] = ..., newInviteLinkAccess: _Optional[_Union[_Groups_pb2.AccessControl.AccessRequired, str]] = ..., newRequestingMembers: _Optional[_Iterable[_Union[DecryptedRequestingMember, _Mapping]]] = ..., deleteRequestingMembers: _Optional[_Iterable[bytes]] = ..., promoteRequestingMembers: _Optional[_Iterable[_Union[DecryptedApproveMember, _Mapping]]] = ..., newInviteLinkPassword: _Optional[bytes] = ..., newDescription: _Optional[_Union[DecryptedString, _Mapping]] = ..., newIsAnnouncementGroup: _Optional[_Union[EnabledState, str]] = ..., newBannedMembers: _Optional[_Iterable[_Union[DecryptedBannedMember, _Mapping]]] = ..., deleteBannedMembers: _Optional[_Iterable[_Union[DecryptedBannedMember, _Mapping]]] = ..., promotePendingPniAciMembers: _Optional[_Iterable[_Union[DecryptedMember, _Mapping]]] = ...) -> None: ...

class DecryptedString(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: str
    def __init__(self, value: _Optional[str] = ...) -> None: ...

class DecryptedTimer(_message.Message):
    __slots__ = ("duration",)
    DURATION_FIELD_NUMBER: _ClassVar[int]
    duration: int
    def __init__(self, duration: _Optional[int] = ...) -> None: ...

class DecryptedGroupJoinInfo(_message.Message):
    __slots__ = ("title", "avatar", "memberCount", "addFromInviteLink", "revision", "pendingAdminApproval", "description", "isAnnouncementGroup")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    MEMBERCOUNT_FIELD_NUMBER: _ClassVar[int]
    ADDFROMINVITELINK_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    PENDINGADMINAPPROVAL_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ISANNOUNCEMENTGROUP_FIELD_NUMBER: _ClassVar[int]
    title: str
    avatar: str
    memberCount: int
    addFromInviteLink: _Groups_pb2.AccessControl.AccessRequired
    revision: int
    pendingAdminApproval: bool
    description: str
    isAnnouncementGroup: bool
    def __init__(self, title: _Optional[str] = ..., avatar: _Optional[str] = ..., memberCount: _Optional[int] = ..., addFromInviteLink: _Optional[_Union[_Groups_pb2.AccessControl.AccessRequired, str]] = ..., revision: _Optional[int] = ..., pendingAdminApproval: bool = ..., description: _Optional[str] = ..., isAnnouncementGroup: bool = ...) -> None: ...
