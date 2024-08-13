from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AvatarUploadAttributes(_message.Message):
    __slots__ = ("key", "credential", "acl", "algorithm", "date", "policy", "signature")
    KEY_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    ACL_FIELD_NUMBER: _ClassVar[int]
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    DATE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    key: str
    credential: str
    acl: str
    algorithm: str
    date: str
    policy: str
    signature: str
    def __init__(self, key: _Optional[str] = ..., credential: _Optional[str] = ..., acl: _Optional[str] = ..., algorithm: _Optional[str] = ..., date: _Optional[str] = ..., policy: _Optional[str] = ..., signature: _Optional[str] = ...) -> None: ...

class Member(_message.Message):
    __slots__ = ("userId", "role", "profileKey", "presentation", "joinedAtRevision")
    class Role(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[Member.Role]
        DEFAULT: _ClassVar[Member.Role]
        ADMINISTRATOR: _ClassVar[Member.Role]
    UNKNOWN: Member.Role
    DEFAULT: Member.Role
    ADMINISTRATOR: Member.Role
    USERID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    PRESENTATION_FIELD_NUMBER: _ClassVar[int]
    JOINEDATREVISION_FIELD_NUMBER: _ClassVar[int]
    userId: bytes
    role: Member.Role
    profileKey: bytes
    presentation: bytes
    joinedAtRevision: int
    def __init__(self, userId: _Optional[bytes] = ..., role: _Optional[_Union[Member.Role, str]] = ..., profileKey: _Optional[bytes] = ..., presentation: _Optional[bytes] = ..., joinedAtRevision: _Optional[int] = ...) -> None: ...

class PendingMember(_message.Message):
    __slots__ = ("member", "addedByUserId", "timestamp")
    MEMBER_FIELD_NUMBER: _ClassVar[int]
    ADDEDBYUSERID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    member: Member
    addedByUserId: bytes
    timestamp: int
    def __init__(self, member: _Optional[_Union[Member, _Mapping]] = ..., addedByUserId: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...

class RequestingMember(_message.Message):
    __slots__ = ("userId", "profileKey", "presentation", "timestamp")
    USERID_FIELD_NUMBER: _ClassVar[int]
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    PRESENTATION_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    userId: bytes
    profileKey: bytes
    presentation: bytes
    timestamp: int
    def __init__(self, userId: _Optional[bytes] = ..., profileKey: _Optional[bytes] = ..., presentation: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...

class BannedMember(_message.Message):
    __slots__ = ("userId", "timestamp")
    USERID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    userId: bytes
    timestamp: int
    def __init__(self, userId: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...

class AccessControl(_message.Message):
    __slots__ = ("attributes", "members", "addFromInviteLink")
    class AccessRequired(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[AccessControl.AccessRequired]
        ANY: _ClassVar[AccessControl.AccessRequired]
        MEMBER: _ClassVar[AccessControl.AccessRequired]
        ADMINISTRATOR: _ClassVar[AccessControl.AccessRequired]
        UNSATISFIABLE: _ClassVar[AccessControl.AccessRequired]
    UNKNOWN: AccessControl.AccessRequired
    ANY: AccessControl.AccessRequired
    MEMBER: AccessControl.AccessRequired
    ADMINISTRATOR: AccessControl.AccessRequired
    UNSATISFIABLE: AccessControl.AccessRequired
    ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    ADDFROMINVITELINK_FIELD_NUMBER: _ClassVar[int]
    attributes: AccessControl.AccessRequired
    members: AccessControl.AccessRequired
    addFromInviteLink: AccessControl.AccessRequired
    def __init__(self, attributes: _Optional[_Union[AccessControl.AccessRequired, str]] = ..., members: _Optional[_Union[AccessControl.AccessRequired, str]] = ..., addFromInviteLink: _Optional[_Union[AccessControl.AccessRequired, str]] = ...) -> None: ...

class Group(_message.Message):
    __slots__ = ("publicKey", "title", "avatar", "disappearingMessagesTimer", "accessControl", "revision", "members", "pendingMembers", "requestingMembers", "inviteLinkPassword", "description", "announcementsOnly", "bannedMembers")
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
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
    ANNOUNCEMENTSONLY_FIELD_NUMBER: _ClassVar[int]
    BANNEDMEMBERS_FIELD_NUMBER: _ClassVar[int]
    publicKey: bytes
    title: bytes
    avatar: str
    disappearingMessagesTimer: bytes
    accessControl: AccessControl
    revision: int
    members: _containers.RepeatedCompositeFieldContainer[Member]
    pendingMembers: _containers.RepeatedCompositeFieldContainer[PendingMember]
    requestingMembers: _containers.RepeatedCompositeFieldContainer[RequestingMember]
    inviteLinkPassword: bytes
    description: bytes
    announcementsOnly: bool
    bannedMembers: _containers.RepeatedCompositeFieldContainer[BannedMember]
    def __init__(self, publicKey: _Optional[bytes] = ..., title: _Optional[bytes] = ..., avatar: _Optional[str] = ..., disappearingMessagesTimer: _Optional[bytes] = ..., accessControl: _Optional[_Union[AccessControl, _Mapping]] = ..., revision: _Optional[int] = ..., members: _Optional[_Iterable[_Union[Member, _Mapping]]] = ..., pendingMembers: _Optional[_Iterable[_Union[PendingMember, _Mapping]]] = ..., requestingMembers: _Optional[_Iterable[_Union[RequestingMember, _Mapping]]] = ..., inviteLinkPassword: _Optional[bytes] = ..., description: _Optional[bytes] = ..., announcementsOnly: bool = ..., bannedMembers: _Optional[_Iterable[_Union[BannedMember, _Mapping]]] = ...) -> None: ...

class GroupChange(_message.Message):
    __slots__ = ("actions", "serverSignature", "changeEpoch")
    class Actions(_message.Message):
        __slots__ = ("sourceServiceId", "revision", "addMembers", "deleteMembers", "modifyMemberRoles", "modifyMemberProfileKeys", "addPendingMembers", "deletePendingMembers", "promotePendingMembers", "modifyTitle", "modifyAvatar", "modifyDisappearingMessagesTimer", "modifyAttributesAccess", "modifyMemberAccess", "modifyAddFromInviteLinkAccess", "addRequestingMembers", "deleteRequestingMembers", "promoteRequestingMembers", "modifyInviteLinkPassword", "modifyDescription", "modifyAnnouncementsOnly", "addBannedMembers", "deleteBannedMembers", "promotePendingPniAciMembers")
        class AddMemberAction(_message.Message):
            __slots__ = ("added", "joinFromInviteLink")
            ADDED_FIELD_NUMBER: _ClassVar[int]
            JOINFROMINVITELINK_FIELD_NUMBER: _ClassVar[int]
            added: Member
            joinFromInviteLink: bool
            def __init__(self, added: _Optional[_Union[Member, _Mapping]] = ..., joinFromInviteLink: bool = ...) -> None: ...
        class DeleteMemberAction(_message.Message):
            __slots__ = ("deletedUserId",)
            DELETEDUSERID_FIELD_NUMBER: _ClassVar[int]
            deletedUserId: bytes
            def __init__(self, deletedUserId: _Optional[bytes] = ...) -> None: ...
        class ModifyMemberRoleAction(_message.Message):
            __slots__ = ("userId", "role")
            USERID_FIELD_NUMBER: _ClassVar[int]
            ROLE_FIELD_NUMBER: _ClassVar[int]
            userId: bytes
            role: Member.Role
            def __init__(self, userId: _Optional[bytes] = ..., role: _Optional[_Union[Member.Role, str]] = ...) -> None: ...
        class ModifyMemberProfileKeyAction(_message.Message):
            __slots__ = ("presentation", "user_id", "profile_key")
            PRESENTATION_FIELD_NUMBER: _ClassVar[int]
            USER_ID_FIELD_NUMBER: _ClassVar[int]
            PROFILE_KEY_FIELD_NUMBER: _ClassVar[int]
            presentation: bytes
            user_id: bytes
            profile_key: bytes
            def __init__(self, presentation: _Optional[bytes] = ..., user_id: _Optional[bytes] = ..., profile_key: _Optional[bytes] = ...) -> None: ...
        class AddPendingMemberAction(_message.Message):
            __slots__ = ("added",)
            ADDED_FIELD_NUMBER: _ClassVar[int]
            added: PendingMember
            def __init__(self, added: _Optional[_Union[PendingMember, _Mapping]] = ...) -> None: ...
        class DeletePendingMemberAction(_message.Message):
            __slots__ = ("deletedUserId",)
            DELETEDUSERID_FIELD_NUMBER: _ClassVar[int]
            deletedUserId: bytes
            def __init__(self, deletedUserId: _Optional[bytes] = ...) -> None: ...
        class PromotePendingMemberAction(_message.Message):
            __slots__ = ("presentation", "user_id", "profile_key")
            PRESENTATION_FIELD_NUMBER: _ClassVar[int]
            USER_ID_FIELD_NUMBER: _ClassVar[int]
            PROFILE_KEY_FIELD_NUMBER: _ClassVar[int]
            presentation: bytes
            user_id: bytes
            profile_key: bytes
            def __init__(self, presentation: _Optional[bytes] = ..., user_id: _Optional[bytes] = ..., profile_key: _Optional[bytes] = ...) -> None: ...
        class PromotePendingPniAciMemberProfileKeyAction(_message.Message):
            __slots__ = ("presentation", "userId", "pni", "profileKey")
            PRESENTATION_FIELD_NUMBER: _ClassVar[int]
            USERID_FIELD_NUMBER: _ClassVar[int]
            PNI_FIELD_NUMBER: _ClassVar[int]
            PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
            presentation: bytes
            userId: bytes
            pni: bytes
            profileKey: bytes
            def __init__(self, presentation: _Optional[bytes] = ..., userId: _Optional[bytes] = ..., pni: _Optional[bytes] = ..., profileKey: _Optional[bytes] = ...) -> None: ...
        class AddRequestingMemberAction(_message.Message):
            __slots__ = ("added",)
            ADDED_FIELD_NUMBER: _ClassVar[int]
            added: RequestingMember
            def __init__(self, added: _Optional[_Union[RequestingMember, _Mapping]] = ...) -> None: ...
        class DeleteRequestingMemberAction(_message.Message):
            __slots__ = ("deletedUserId",)
            DELETEDUSERID_FIELD_NUMBER: _ClassVar[int]
            deletedUserId: bytes
            def __init__(self, deletedUserId: _Optional[bytes] = ...) -> None: ...
        class PromoteRequestingMemberAction(_message.Message):
            __slots__ = ("userId", "role")
            USERID_FIELD_NUMBER: _ClassVar[int]
            ROLE_FIELD_NUMBER: _ClassVar[int]
            userId: bytes
            role: Member.Role
            def __init__(self, userId: _Optional[bytes] = ..., role: _Optional[_Union[Member.Role, str]] = ...) -> None: ...
        class AddBannedMemberAction(_message.Message):
            __slots__ = ("added",)
            ADDED_FIELD_NUMBER: _ClassVar[int]
            added: BannedMember
            def __init__(self, added: _Optional[_Union[BannedMember, _Mapping]] = ...) -> None: ...
        class DeleteBannedMemberAction(_message.Message):
            __slots__ = ("deletedUserId",)
            DELETEDUSERID_FIELD_NUMBER: _ClassVar[int]
            deletedUserId: bytes
            def __init__(self, deletedUserId: _Optional[bytes] = ...) -> None: ...
        class ModifyTitleAction(_message.Message):
            __slots__ = ("title",)
            TITLE_FIELD_NUMBER: _ClassVar[int]
            title: bytes
            def __init__(self, title: _Optional[bytes] = ...) -> None: ...
        class ModifyDescriptionAction(_message.Message):
            __slots__ = ("description",)
            DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
            description: bytes
            def __init__(self, description: _Optional[bytes] = ...) -> None: ...
        class ModifyAvatarAction(_message.Message):
            __slots__ = ("avatar",)
            AVATAR_FIELD_NUMBER: _ClassVar[int]
            avatar: str
            def __init__(self, avatar: _Optional[str] = ...) -> None: ...
        class ModifyDisappearingMessagesTimerAction(_message.Message):
            __slots__ = ("timer",)
            TIMER_FIELD_NUMBER: _ClassVar[int]
            timer: bytes
            def __init__(self, timer: _Optional[bytes] = ...) -> None: ...
        class ModifyAttributesAccessControlAction(_message.Message):
            __slots__ = ("attributesAccess",)
            ATTRIBUTESACCESS_FIELD_NUMBER: _ClassVar[int]
            attributesAccess: AccessControl.AccessRequired
            def __init__(self, attributesAccess: _Optional[_Union[AccessControl.AccessRequired, str]] = ...) -> None: ...
        class ModifyMembersAccessControlAction(_message.Message):
            __slots__ = ("membersAccess",)
            MEMBERSACCESS_FIELD_NUMBER: _ClassVar[int]
            membersAccess: AccessControl.AccessRequired
            def __init__(self, membersAccess: _Optional[_Union[AccessControl.AccessRequired, str]] = ...) -> None: ...
        class ModifyAddFromInviteLinkAccessControlAction(_message.Message):
            __slots__ = ("addFromInviteLinkAccess",)
            ADDFROMINVITELINKACCESS_FIELD_NUMBER: _ClassVar[int]
            addFromInviteLinkAccess: AccessControl.AccessRequired
            def __init__(self, addFromInviteLinkAccess: _Optional[_Union[AccessControl.AccessRequired, str]] = ...) -> None: ...
        class ModifyInviteLinkPasswordAction(_message.Message):
            __slots__ = ("inviteLinkPassword",)
            INVITELINKPASSWORD_FIELD_NUMBER: _ClassVar[int]
            inviteLinkPassword: bytes
            def __init__(self, inviteLinkPassword: _Optional[bytes] = ...) -> None: ...
        class ModifyAnnouncementsOnlyAction(_message.Message):
            __slots__ = ("announcementsOnly",)
            ANNOUNCEMENTSONLY_FIELD_NUMBER: _ClassVar[int]
            announcementsOnly: bool
            def __init__(self, announcementsOnly: bool = ...) -> None: ...
        SOURCESERVICEID_FIELD_NUMBER: _ClassVar[int]
        REVISION_FIELD_NUMBER: _ClassVar[int]
        ADDMEMBERS_FIELD_NUMBER: _ClassVar[int]
        DELETEMEMBERS_FIELD_NUMBER: _ClassVar[int]
        MODIFYMEMBERROLES_FIELD_NUMBER: _ClassVar[int]
        MODIFYMEMBERPROFILEKEYS_FIELD_NUMBER: _ClassVar[int]
        ADDPENDINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
        DELETEPENDINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
        PROMOTEPENDINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
        MODIFYTITLE_FIELD_NUMBER: _ClassVar[int]
        MODIFYAVATAR_FIELD_NUMBER: _ClassVar[int]
        MODIFYDISAPPEARINGMESSAGESTIMER_FIELD_NUMBER: _ClassVar[int]
        MODIFYATTRIBUTESACCESS_FIELD_NUMBER: _ClassVar[int]
        MODIFYMEMBERACCESS_FIELD_NUMBER: _ClassVar[int]
        MODIFYADDFROMINVITELINKACCESS_FIELD_NUMBER: _ClassVar[int]
        ADDREQUESTINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
        DELETEREQUESTINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
        PROMOTEREQUESTINGMEMBERS_FIELD_NUMBER: _ClassVar[int]
        MODIFYINVITELINKPASSWORD_FIELD_NUMBER: _ClassVar[int]
        MODIFYDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
        MODIFYANNOUNCEMENTSONLY_FIELD_NUMBER: _ClassVar[int]
        ADDBANNEDMEMBERS_FIELD_NUMBER: _ClassVar[int]
        DELETEBANNEDMEMBERS_FIELD_NUMBER: _ClassVar[int]
        PROMOTEPENDINGPNIACIMEMBERS_FIELD_NUMBER: _ClassVar[int]
        sourceServiceId: bytes
        revision: int
        addMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.AddMemberAction]
        deleteMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.DeleteMemberAction]
        modifyMemberRoles: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.ModifyMemberRoleAction]
        modifyMemberProfileKeys: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.ModifyMemberProfileKeyAction]
        addPendingMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.AddPendingMemberAction]
        deletePendingMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.DeletePendingMemberAction]
        promotePendingMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.PromotePendingMemberAction]
        modifyTitle: GroupChange.Actions.ModifyTitleAction
        modifyAvatar: GroupChange.Actions.ModifyAvatarAction
        modifyDisappearingMessagesTimer: GroupChange.Actions.ModifyDisappearingMessagesTimerAction
        modifyAttributesAccess: GroupChange.Actions.ModifyAttributesAccessControlAction
        modifyMemberAccess: GroupChange.Actions.ModifyMembersAccessControlAction
        modifyAddFromInviteLinkAccess: GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction
        addRequestingMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.AddRequestingMemberAction]
        deleteRequestingMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.DeleteRequestingMemberAction]
        promoteRequestingMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.PromoteRequestingMemberAction]
        modifyInviteLinkPassword: GroupChange.Actions.ModifyInviteLinkPasswordAction
        modifyDescription: GroupChange.Actions.ModifyDescriptionAction
        modifyAnnouncementsOnly: GroupChange.Actions.ModifyAnnouncementsOnlyAction
        addBannedMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.AddBannedMemberAction]
        deleteBannedMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.DeleteBannedMemberAction]
        promotePendingPniAciMembers: _containers.RepeatedCompositeFieldContainer[GroupChange.Actions.PromotePendingPniAciMemberProfileKeyAction]
        def __init__(self, sourceServiceId: _Optional[bytes] = ..., revision: _Optional[int] = ..., addMembers: _Optional[_Iterable[_Union[GroupChange.Actions.AddMemberAction, _Mapping]]] = ..., deleteMembers: _Optional[_Iterable[_Union[GroupChange.Actions.DeleteMemberAction, _Mapping]]] = ..., modifyMemberRoles: _Optional[_Iterable[_Union[GroupChange.Actions.ModifyMemberRoleAction, _Mapping]]] = ..., modifyMemberProfileKeys: _Optional[_Iterable[_Union[GroupChange.Actions.ModifyMemberProfileKeyAction, _Mapping]]] = ..., addPendingMembers: _Optional[_Iterable[_Union[GroupChange.Actions.AddPendingMemberAction, _Mapping]]] = ..., deletePendingMembers: _Optional[_Iterable[_Union[GroupChange.Actions.DeletePendingMemberAction, _Mapping]]] = ..., promotePendingMembers: _Optional[_Iterable[_Union[GroupChange.Actions.PromotePendingMemberAction, _Mapping]]] = ..., modifyTitle: _Optional[_Union[GroupChange.Actions.ModifyTitleAction, _Mapping]] = ..., modifyAvatar: _Optional[_Union[GroupChange.Actions.ModifyAvatarAction, _Mapping]] = ..., modifyDisappearingMessagesTimer: _Optional[_Union[GroupChange.Actions.ModifyDisappearingMessagesTimerAction, _Mapping]] = ..., modifyAttributesAccess: _Optional[_Union[GroupChange.Actions.ModifyAttributesAccessControlAction, _Mapping]] = ..., modifyMemberAccess: _Optional[_Union[GroupChange.Actions.ModifyMembersAccessControlAction, _Mapping]] = ..., modifyAddFromInviteLinkAccess: _Optional[_Union[GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction, _Mapping]] = ..., addRequestingMembers: _Optional[_Iterable[_Union[GroupChange.Actions.AddRequestingMemberAction, _Mapping]]] = ..., deleteRequestingMembers: _Optional[_Iterable[_Union[GroupChange.Actions.DeleteRequestingMemberAction, _Mapping]]] = ..., promoteRequestingMembers: _Optional[_Iterable[_Union[GroupChange.Actions.PromoteRequestingMemberAction, _Mapping]]] = ..., modifyInviteLinkPassword: _Optional[_Union[GroupChange.Actions.ModifyInviteLinkPasswordAction, _Mapping]] = ..., modifyDescription: _Optional[_Union[GroupChange.Actions.ModifyDescriptionAction, _Mapping]] = ..., modifyAnnouncementsOnly: _Optional[_Union[GroupChange.Actions.ModifyAnnouncementsOnlyAction, _Mapping]] = ..., addBannedMembers: _Optional[_Iterable[_Union[GroupChange.Actions.AddBannedMemberAction, _Mapping]]] = ..., deleteBannedMembers: _Optional[_Iterable[_Union[GroupChange.Actions.DeleteBannedMemberAction, _Mapping]]] = ..., promotePendingPniAciMembers: _Optional[_Iterable[_Union[GroupChange.Actions.PromotePendingPniAciMemberProfileKeyAction, _Mapping]]] = ...) -> None: ...
    ACTIONS_FIELD_NUMBER: _ClassVar[int]
    SERVERSIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CHANGEEPOCH_FIELD_NUMBER: _ClassVar[int]
    actions: bytes
    serverSignature: bytes
    changeEpoch: int
    def __init__(self, actions: _Optional[bytes] = ..., serverSignature: _Optional[bytes] = ..., changeEpoch: _Optional[int] = ...) -> None: ...

class GroupResponse(_message.Message):
    __slots__ = ("group", "groupSendEndorsementsResponse")
    GROUP_FIELD_NUMBER: _ClassVar[int]
    GROUPSENDENDORSEMENTSRESPONSE_FIELD_NUMBER: _ClassVar[int]
    group: Group
    groupSendEndorsementsResponse: bytes
    def __init__(self, group: _Optional[_Union[Group, _Mapping]] = ..., groupSendEndorsementsResponse: _Optional[bytes] = ...) -> None: ...

class GroupChanges(_message.Message):
    __slots__ = ("groupChanges", "groupSendEndorsementsResponse")
    class GroupChangeState(_message.Message):
        __slots__ = ("groupChange", "groupState")
        GROUPCHANGE_FIELD_NUMBER: _ClassVar[int]
        GROUPSTATE_FIELD_NUMBER: _ClassVar[int]
        groupChange: GroupChange
        groupState: Group
        def __init__(self, groupChange: _Optional[_Union[GroupChange, _Mapping]] = ..., groupState: _Optional[_Union[Group, _Mapping]] = ...) -> None: ...
    GROUPCHANGES_FIELD_NUMBER: _ClassVar[int]
    GROUPSENDENDORSEMENTSRESPONSE_FIELD_NUMBER: _ClassVar[int]
    groupChanges: _containers.RepeatedCompositeFieldContainer[GroupChanges.GroupChangeState]
    groupSendEndorsementsResponse: bytes
    def __init__(self, groupChanges: _Optional[_Iterable[_Union[GroupChanges.GroupChangeState, _Mapping]]] = ..., groupSendEndorsementsResponse: _Optional[bytes] = ...) -> None: ...

class GroupChangeResponse(_message.Message):
    __slots__ = ("groupChange", "groupSendEndorsementsResponse")
    GROUPCHANGE_FIELD_NUMBER: _ClassVar[int]
    GROUPSENDENDORSEMENTSRESPONSE_FIELD_NUMBER: _ClassVar[int]
    groupChange: GroupChange
    groupSendEndorsementsResponse: bytes
    def __init__(self, groupChange: _Optional[_Union[GroupChange, _Mapping]] = ..., groupSendEndorsementsResponse: _Optional[bytes] = ...) -> None: ...

class GroupAttributeBlob(_message.Message):
    __slots__ = ("title", "avatar", "disappearingMessagesDuration", "description")
    TITLE_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    DISAPPEARINGMESSAGESDURATION_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    title: str
    avatar: bytes
    disappearingMessagesDuration: int
    description: str
    def __init__(self, title: _Optional[str] = ..., avatar: _Optional[bytes] = ..., disappearingMessagesDuration: _Optional[int] = ..., description: _Optional[str] = ...) -> None: ...

class GroupInviteLink(_message.Message):
    __slots__ = ("v1Contents",)
    class GroupInviteLinkContentsV1(_message.Message):
        __slots__ = ("groupMasterKey", "inviteLinkPassword")
        GROUPMASTERKEY_FIELD_NUMBER: _ClassVar[int]
        INVITELINKPASSWORD_FIELD_NUMBER: _ClassVar[int]
        groupMasterKey: bytes
        inviteLinkPassword: bytes
        def __init__(self, groupMasterKey: _Optional[bytes] = ..., inviteLinkPassword: _Optional[bytes] = ...) -> None: ...
    V1CONTENTS_FIELD_NUMBER: _ClassVar[int]
    v1Contents: GroupInviteLink.GroupInviteLinkContentsV1
    def __init__(self, v1Contents: _Optional[_Union[GroupInviteLink.GroupInviteLinkContentsV1, _Mapping]] = ...) -> None: ...

class GroupJoinInfo(_message.Message):
    __slots__ = ("publicKey", "title", "avatar", "memberCount", "addFromInviteLink", "revision", "pendingAdminApproval", "description")
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    MEMBERCOUNT_FIELD_NUMBER: _ClassVar[int]
    ADDFROMINVITELINK_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    PENDINGADMINAPPROVAL_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    publicKey: bytes
    title: bytes
    avatar: str
    memberCount: int
    addFromInviteLink: AccessControl.AccessRequired
    revision: int
    pendingAdminApproval: bool
    description: bytes
    def __init__(self, publicKey: _Optional[bytes] = ..., title: _Optional[bytes] = ..., avatar: _Optional[str] = ..., memberCount: _Optional[int] = ..., addFromInviteLink: _Optional[_Union[AccessControl.AccessRequired, str]] = ..., revision: _Optional[int] = ..., pendingAdminApproval: bool = ..., description: _Optional[bytes] = ...) -> None: ...

class GroupExternalCredential(_message.Message):
    __slots__ = ("token",)
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: str
    def __init__(self, token: _Optional[str] = ...) -> None: ...
