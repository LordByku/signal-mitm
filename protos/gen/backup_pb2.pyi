from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GroupV2AccessLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNKNOWN: _ClassVar[GroupV2AccessLevel]
    ANY: _ClassVar[GroupV2AccessLevel]
    MEMBER: _ClassVar[GroupV2AccessLevel]
    ADMINISTRATOR: _ClassVar[GroupV2AccessLevel]
    UNSATISFIABLE: _ClassVar[GroupV2AccessLevel]
UNKNOWN: GroupV2AccessLevel
ANY: GroupV2AccessLevel
MEMBER: GroupV2AccessLevel
ADMINISTRATOR: GroupV2AccessLevel
UNSATISFIABLE: GroupV2AccessLevel

class BackupInfo(_message.Message):
    __slots__ = ("version", "backupTimeMs")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    BACKUPTIMEMS_FIELD_NUMBER: _ClassVar[int]
    version: int
    backupTimeMs: int
    def __init__(self, version: _Optional[int] = ..., backupTimeMs: _Optional[int] = ...) -> None: ...

class Frame(_message.Message):
    __slots__ = ("account", "recipient", "chat", "chatItem", "stickerPack", "adHocCall")
    ACCOUNT_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    CHAT_FIELD_NUMBER: _ClassVar[int]
    CHATITEM_FIELD_NUMBER: _ClassVar[int]
    STICKERPACK_FIELD_NUMBER: _ClassVar[int]
    ADHOCCALL_FIELD_NUMBER: _ClassVar[int]
    account: AccountData
    recipient: Recipient
    chat: Chat
    chatItem: ChatItem
    stickerPack: StickerPack
    adHocCall: AdHocCall
    def __init__(self, account: _Optional[_Union[AccountData, _Mapping]] = ..., recipient: _Optional[_Union[Recipient, _Mapping]] = ..., chat: _Optional[_Union[Chat, _Mapping]] = ..., chatItem: _Optional[_Union[ChatItem, _Mapping]] = ..., stickerPack: _Optional[_Union[StickerPack, _Mapping]] = ..., adHocCall: _Optional[_Union[AdHocCall, _Mapping]] = ...) -> None: ...

class AccountData(_message.Message):
    __slots__ = ("profileKey", "username", "usernameLink", "givenName", "familyName", "avatarUrlPath", "donationSubscriberData", "backupsSubscriberData", "accountSettings")
    class PhoneNumberSharingMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[AccountData.PhoneNumberSharingMode]
        EVERYBODY: _ClassVar[AccountData.PhoneNumberSharingMode]
        NOBODY: _ClassVar[AccountData.PhoneNumberSharingMode]
    UNKNOWN: AccountData.PhoneNumberSharingMode
    EVERYBODY: AccountData.PhoneNumberSharingMode
    NOBODY: AccountData.PhoneNumberSharingMode
    class UsernameLink(_message.Message):
        __slots__ = ("entropy", "serverId", "color")
        class Color(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[AccountData.UsernameLink.Color]
            BLUE: _ClassVar[AccountData.UsernameLink.Color]
            WHITE: _ClassVar[AccountData.UsernameLink.Color]
            GREY: _ClassVar[AccountData.UsernameLink.Color]
            OLIVE: _ClassVar[AccountData.UsernameLink.Color]
            GREEN: _ClassVar[AccountData.UsernameLink.Color]
            ORANGE: _ClassVar[AccountData.UsernameLink.Color]
            PINK: _ClassVar[AccountData.UsernameLink.Color]
            PURPLE: _ClassVar[AccountData.UsernameLink.Color]
        UNKNOWN: AccountData.UsernameLink.Color
        BLUE: AccountData.UsernameLink.Color
        WHITE: AccountData.UsernameLink.Color
        GREY: AccountData.UsernameLink.Color
        OLIVE: AccountData.UsernameLink.Color
        GREEN: AccountData.UsernameLink.Color
        ORANGE: AccountData.UsernameLink.Color
        PINK: AccountData.UsernameLink.Color
        PURPLE: AccountData.UsernameLink.Color
        ENTROPY_FIELD_NUMBER: _ClassVar[int]
        SERVERID_FIELD_NUMBER: _ClassVar[int]
        COLOR_FIELD_NUMBER: _ClassVar[int]
        entropy: bytes
        serverId: bytes
        color: AccountData.UsernameLink.Color
        def __init__(self, entropy: _Optional[bytes] = ..., serverId: _Optional[bytes] = ..., color: _Optional[_Union[AccountData.UsernameLink.Color, str]] = ...) -> None: ...
    class AccountSettings(_message.Message):
        __slots__ = ("readReceipts", "sealedSenderIndicators", "typingIndicators", "linkPreviews", "notDiscoverableByPhoneNumber", "preferContactAvatars", "universalExpireTimerSeconds", "preferredReactionEmoji", "displayBadgesOnProfile", "keepMutedChatsArchived", "hasSetMyStoriesPrivacy", "hasViewedOnboardingStory", "storiesDisabled", "storyViewReceiptsEnabled", "hasSeenGroupStoryEducationSheet", "hasCompletedUsernameOnboarding", "phoneNumberSharingMode", "defaultChatStyle", "customChatColors")
        READRECEIPTS_FIELD_NUMBER: _ClassVar[int]
        SEALEDSENDERINDICATORS_FIELD_NUMBER: _ClassVar[int]
        TYPINGINDICATORS_FIELD_NUMBER: _ClassVar[int]
        LINKPREVIEWS_FIELD_NUMBER: _ClassVar[int]
        NOTDISCOVERABLEBYPHONENUMBER_FIELD_NUMBER: _ClassVar[int]
        PREFERCONTACTAVATARS_FIELD_NUMBER: _ClassVar[int]
        UNIVERSALEXPIRETIMERSECONDS_FIELD_NUMBER: _ClassVar[int]
        PREFERREDREACTIONEMOJI_FIELD_NUMBER: _ClassVar[int]
        DISPLAYBADGESONPROFILE_FIELD_NUMBER: _ClassVar[int]
        KEEPMUTEDCHATSARCHIVED_FIELD_NUMBER: _ClassVar[int]
        HASSETMYSTORIESPRIVACY_FIELD_NUMBER: _ClassVar[int]
        HASVIEWEDONBOARDINGSTORY_FIELD_NUMBER: _ClassVar[int]
        STORIESDISABLED_FIELD_NUMBER: _ClassVar[int]
        STORYVIEWRECEIPTSENABLED_FIELD_NUMBER: _ClassVar[int]
        HASSEENGROUPSTORYEDUCATIONSHEET_FIELD_NUMBER: _ClassVar[int]
        HASCOMPLETEDUSERNAMEONBOARDING_FIELD_NUMBER: _ClassVar[int]
        PHONENUMBERSHARINGMODE_FIELD_NUMBER: _ClassVar[int]
        DEFAULTCHATSTYLE_FIELD_NUMBER: _ClassVar[int]
        CUSTOMCHATCOLORS_FIELD_NUMBER: _ClassVar[int]
        readReceipts: bool
        sealedSenderIndicators: bool
        typingIndicators: bool
        linkPreviews: bool
        notDiscoverableByPhoneNumber: bool
        preferContactAvatars: bool
        universalExpireTimerSeconds: int
        preferredReactionEmoji: _containers.RepeatedScalarFieldContainer[str]
        displayBadgesOnProfile: bool
        keepMutedChatsArchived: bool
        hasSetMyStoriesPrivacy: bool
        hasViewedOnboardingStory: bool
        storiesDisabled: bool
        storyViewReceiptsEnabled: bool
        hasSeenGroupStoryEducationSheet: bool
        hasCompletedUsernameOnboarding: bool
        phoneNumberSharingMode: AccountData.PhoneNumberSharingMode
        defaultChatStyle: ChatStyle
        customChatColors: _containers.RepeatedCompositeFieldContainer[ChatStyle.CustomChatColor]
        def __init__(self, readReceipts: bool = ..., sealedSenderIndicators: bool = ..., typingIndicators: bool = ..., linkPreviews: bool = ..., notDiscoverableByPhoneNumber: bool = ..., preferContactAvatars: bool = ..., universalExpireTimerSeconds: _Optional[int] = ..., preferredReactionEmoji: _Optional[_Iterable[str]] = ..., displayBadgesOnProfile: bool = ..., keepMutedChatsArchived: bool = ..., hasSetMyStoriesPrivacy: bool = ..., hasViewedOnboardingStory: bool = ..., storiesDisabled: bool = ..., storyViewReceiptsEnabled: bool = ..., hasSeenGroupStoryEducationSheet: bool = ..., hasCompletedUsernameOnboarding: bool = ..., phoneNumberSharingMode: _Optional[_Union[AccountData.PhoneNumberSharingMode, str]] = ..., defaultChatStyle: _Optional[_Union[ChatStyle, _Mapping]] = ..., customChatColors: _Optional[_Iterable[_Union[ChatStyle.CustomChatColor, _Mapping]]] = ...) -> None: ...
    class SubscriberData(_message.Message):
        __slots__ = ("subscriberId", "currencyCode", "manuallyCancelled")
        SUBSCRIBERID_FIELD_NUMBER: _ClassVar[int]
        CURRENCYCODE_FIELD_NUMBER: _ClassVar[int]
        MANUALLYCANCELLED_FIELD_NUMBER: _ClassVar[int]
        subscriberId: bytes
        currencyCode: str
        manuallyCancelled: bool
        def __init__(self, subscriberId: _Optional[bytes] = ..., currencyCode: _Optional[str] = ..., manuallyCancelled: bool = ...) -> None: ...
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    USERNAMELINK_FIELD_NUMBER: _ClassVar[int]
    GIVENNAME_FIELD_NUMBER: _ClassVar[int]
    FAMILYNAME_FIELD_NUMBER: _ClassVar[int]
    AVATARURLPATH_FIELD_NUMBER: _ClassVar[int]
    DONATIONSUBSCRIBERDATA_FIELD_NUMBER: _ClassVar[int]
    BACKUPSSUBSCRIBERDATA_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTSETTINGS_FIELD_NUMBER: _ClassVar[int]
    profileKey: bytes
    username: str
    usernameLink: AccountData.UsernameLink
    givenName: str
    familyName: str
    avatarUrlPath: str
    donationSubscriberData: AccountData.SubscriberData
    backupsSubscriberData: AccountData.SubscriberData
    accountSettings: AccountData.AccountSettings
    def __init__(self, profileKey: _Optional[bytes] = ..., username: _Optional[str] = ..., usernameLink: _Optional[_Union[AccountData.UsernameLink, _Mapping]] = ..., givenName: _Optional[str] = ..., familyName: _Optional[str] = ..., avatarUrlPath: _Optional[str] = ..., donationSubscriberData: _Optional[_Union[AccountData.SubscriberData, _Mapping]] = ..., backupsSubscriberData: _Optional[_Union[AccountData.SubscriberData, _Mapping]] = ..., accountSettings: _Optional[_Union[AccountData.AccountSettings, _Mapping]] = ...) -> None: ...

class Recipient(_message.Message):
    __slots__ = ("id", "contact", "group", "distributionList", "self", "releaseNotes", "callLink")
    ID_FIELD_NUMBER: _ClassVar[int]
    CONTACT_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    DISTRIBUTIONLIST_FIELD_NUMBER: _ClassVar[int]
    SELF_FIELD_NUMBER: _ClassVar[int]
    RELEASENOTES_FIELD_NUMBER: _ClassVar[int]
    CALLLINK_FIELD_NUMBER: _ClassVar[int]
    id: int
    contact: Contact
    group: Group
    distributionList: DistributionListItem
    self: Self
    releaseNotes: ReleaseNotes
    callLink: CallLink
    def __init__(self, id: _Optional[int] = ..., contact: _Optional[_Union[Contact, _Mapping]] = ..., group: _Optional[_Union[Group, _Mapping]] = ..., distributionList: _Optional[_Union[DistributionListItem, _Mapping]] = ..., self: _Optional[_Union[Self, _Mapping]] = ..., releaseNotes: _Optional[_Union[ReleaseNotes, _Mapping]] = ..., callLink: _Optional[_Union[CallLink, _Mapping]] = ...) -> None: ...

class Contact(_message.Message):
    __slots__ = ("aci", "pni", "username", "e164", "blocked", "visibility", "registered", "notRegistered", "profileKey", "profileSharing", "profileGivenName", "profileFamilyName", "hideStory")
    class Visibility(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        VISIBLE: _ClassVar[Contact.Visibility]
        HIDDEN: _ClassVar[Contact.Visibility]
        HIDDEN_MESSAGE_REQUEST: _ClassVar[Contact.Visibility]
    VISIBLE: Contact.Visibility
    HIDDEN: Contact.Visibility
    HIDDEN_MESSAGE_REQUEST: Contact.Visibility
    class Registered(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    class NotRegistered(_message.Message):
        __slots__ = ("unregisteredTimestamp",)
        UNREGISTEREDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        unregisteredTimestamp: int
        def __init__(self, unregisteredTimestamp: _Optional[int] = ...) -> None: ...
    ACI_FIELD_NUMBER: _ClassVar[int]
    PNI_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    E164_FIELD_NUMBER: _ClassVar[int]
    BLOCKED_FIELD_NUMBER: _ClassVar[int]
    VISIBILITY_FIELD_NUMBER: _ClassVar[int]
    REGISTERED_FIELD_NUMBER: _ClassVar[int]
    NOTREGISTERED_FIELD_NUMBER: _ClassVar[int]
    PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
    PROFILESHARING_FIELD_NUMBER: _ClassVar[int]
    PROFILEGIVENNAME_FIELD_NUMBER: _ClassVar[int]
    PROFILEFAMILYNAME_FIELD_NUMBER: _ClassVar[int]
    HIDESTORY_FIELD_NUMBER: _ClassVar[int]
    aci: bytes
    pni: bytes
    username: str
    e164: int
    blocked: bool
    visibility: Contact.Visibility
    registered: Contact.Registered
    notRegistered: Contact.NotRegistered
    profileKey: bytes
    profileSharing: bool
    profileGivenName: str
    profileFamilyName: str
    hideStory: bool
    def __init__(self, aci: _Optional[bytes] = ..., pni: _Optional[bytes] = ..., username: _Optional[str] = ..., e164: _Optional[int] = ..., blocked: bool = ..., visibility: _Optional[_Union[Contact.Visibility, str]] = ..., registered: _Optional[_Union[Contact.Registered, _Mapping]] = ..., notRegistered: _Optional[_Union[Contact.NotRegistered, _Mapping]] = ..., profileKey: _Optional[bytes] = ..., profileSharing: bool = ..., profileGivenName: _Optional[str] = ..., profileFamilyName: _Optional[str] = ..., hideStory: bool = ...) -> None: ...

class Group(_message.Message):
    __slots__ = ("masterKey", "whitelisted", "hideStory", "storySendMode", "snapshot")
    class StorySendMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DEFAULT: _ClassVar[Group.StorySendMode]
        DISABLED: _ClassVar[Group.StorySendMode]
        ENABLED: _ClassVar[Group.StorySendMode]
    DEFAULT: Group.StorySendMode
    DISABLED: Group.StorySendMode
    ENABLED: Group.StorySendMode
    class GroupSnapshot(_message.Message):
        __slots__ = ("publicKey", "title", "description", "avatarUrl", "disappearingMessagesTimer", "accessControl", "version", "members", "membersPendingProfileKey", "membersPendingAdminApproval", "inviteLinkPassword", "announcements_only", "members_banned")
        PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
        TITLE_FIELD_NUMBER: _ClassVar[int]
        DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
        AVATARURL_FIELD_NUMBER: _ClassVar[int]
        DISAPPEARINGMESSAGESTIMER_FIELD_NUMBER: _ClassVar[int]
        ACCESSCONTROL_FIELD_NUMBER: _ClassVar[int]
        VERSION_FIELD_NUMBER: _ClassVar[int]
        MEMBERS_FIELD_NUMBER: _ClassVar[int]
        MEMBERSPENDINGPROFILEKEY_FIELD_NUMBER: _ClassVar[int]
        MEMBERSPENDINGADMINAPPROVAL_FIELD_NUMBER: _ClassVar[int]
        INVITELINKPASSWORD_FIELD_NUMBER: _ClassVar[int]
        ANNOUNCEMENTS_ONLY_FIELD_NUMBER: _ClassVar[int]
        MEMBERS_BANNED_FIELD_NUMBER: _ClassVar[int]
        publicKey: bytes
        title: Group.GroupAttributeBlob
        description: Group.GroupAttributeBlob
        avatarUrl: str
        disappearingMessagesTimer: Group.GroupAttributeBlob
        accessControl: Group.AccessControl
        version: int
        members: _containers.RepeatedCompositeFieldContainer[Group.Member]
        membersPendingProfileKey: _containers.RepeatedCompositeFieldContainer[Group.MemberPendingProfileKey]
        membersPendingAdminApproval: _containers.RepeatedCompositeFieldContainer[Group.MemberPendingAdminApproval]
        inviteLinkPassword: bytes
        announcements_only: bool
        members_banned: _containers.RepeatedCompositeFieldContainer[Group.MemberBanned]
        def __init__(self, publicKey: _Optional[bytes] = ..., title: _Optional[_Union[Group.GroupAttributeBlob, _Mapping]] = ..., description: _Optional[_Union[Group.GroupAttributeBlob, _Mapping]] = ..., avatarUrl: _Optional[str] = ..., disappearingMessagesTimer: _Optional[_Union[Group.GroupAttributeBlob, _Mapping]] = ..., accessControl: _Optional[_Union[Group.AccessControl, _Mapping]] = ..., version: _Optional[int] = ..., members: _Optional[_Iterable[_Union[Group.Member, _Mapping]]] = ..., membersPendingProfileKey: _Optional[_Iterable[_Union[Group.MemberPendingProfileKey, _Mapping]]] = ..., membersPendingAdminApproval: _Optional[_Iterable[_Union[Group.MemberPendingAdminApproval, _Mapping]]] = ..., inviteLinkPassword: _Optional[bytes] = ..., announcements_only: bool = ..., members_banned: _Optional[_Iterable[_Union[Group.MemberBanned, _Mapping]]] = ...) -> None: ...
    class GroupAttributeBlob(_message.Message):
        __slots__ = ("title", "avatar", "disappearingMessagesDuration", "descriptionText")
        TITLE_FIELD_NUMBER: _ClassVar[int]
        AVATAR_FIELD_NUMBER: _ClassVar[int]
        DISAPPEARINGMESSAGESDURATION_FIELD_NUMBER: _ClassVar[int]
        DESCRIPTIONTEXT_FIELD_NUMBER: _ClassVar[int]
        title: str
        avatar: bytes
        disappearingMessagesDuration: int
        descriptionText: str
        def __init__(self, title: _Optional[str] = ..., avatar: _Optional[bytes] = ..., disappearingMessagesDuration: _Optional[int] = ..., descriptionText: _Optional[str] = ...) -> None: ...
    class Member(_message.Message):
        __slots__ = ("userId", "role", "profileKey", "joinedAtVersion")
        class Role(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[Group.Member.Role]
            DEFAULT: _ClassVar[Group.Member.Role]
            ADMINISTRATOR: _ClassVar[Group.Member.Role]
        UNKNOWN: Group.Member.Role
        DEFAULT: Group.Member.Role
        ADMINISTRATOR: Group.Member.Role
        USERID_FIELD_NUMBER: _ClassVar[int]
        ROLE_FIELD_NUMBER: _ClassVar[int]
        PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
        JOINEDATVERSION_FIELD_NUMBER: _ClassVar[int]
        userId: bytes
        role: Group.Member.Role
        profileKey: bytes
        joinedAtVersion: int
        def __init__(self, userId: _Optional[bytes] = ..., role: _Optional[_Union[Group.Member.Role, str]] = ..., profileKey: _Optional[bytes] = ..., joinedAtVersion: _Optional[int] = ...) -> None: ...
    class MemberPendingProfileKey(_message.Message):
        __slots__ = ("member", "addedByUserId", "timestamp")
        MEMBER_FIELD_NUMBER: _ClassVar[int]
        ADDEDBYUSERID_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        member: Group.Member
        addedByUserId: bytes
        timestamp: int
        def __init__(self, member: _Optional[_Union[Group.Member, _Mapping]] = ..., addedByUserId: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...
    class MemberPendingAdminApproval(_message.Message):
        __slots__ = ("userId", "profileKey", "timestamp")
        USERID_FIELD_NUMBER: _ClassVar[int]
        PROFILEKEY_FIELD_NUMBER: _ClassVar[int]
        TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        userId: bytes
        profileKey: bytes
        timestamp: int
        def __init__(self, userId: _Optional[bytes] = ..., profileKey: _Optional[bytes] = ..., timestamp: _Optional[int] = ...) -> None: ...
    class MemberBanned(_message.Message):
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
            UNKNOWN: _ClassVar[Group.AccessControl.AccessRequired]
            ANY: _ClassVar[Group.AccessControl.AccessRequired]
            MEMBER: _ClassVar[Group.AccessControl.AccessRequired]
            ADMINISTRATOR: _ClassVar[Group.AccessControl.AccessRequired]
            UNSATISFIABLE: _ClassVar[Group.AccessControl.AccessRequired]
        UNKNOWN: Group.AccessControl.AccessRequired
        ANY: Group.AccessControl.AccessRequired
        MEMBER: Group.AccessControl.AccessRequired
        ADMINISTRATOR: Group.AccessControl.AccessRequired
        UNSATISFIABLE: Group.AccessControl.AccessRequired
        ATTRIBUTES_FIELD_NUMBER: _ClassVar[int]
        MEMBERS_FIELD_NUMBER: _ClassVar[int]
        ADDFROMINVITELINK_FIELD_NUMBER: _ClassVar[int]
        attributes: Group.AccessControl.AccessRequired
        members: Group.AccessControl.AccessRequired
        addFromInviteLink: Group.AccessControl.AccessRequired
        def __init__(self, attributes: _Optional[_Union[Group.AccessControl.AccessRequired, str]] = ..., members: _Optional[_Union[Group.AccessControl.AccessRequired, str]] = ..., addFromInviteLink: _Optional[_Union[Group.AccessControl.AccessRequired, str]] = ...) -> None: ...
    MASTERKEY_FIELD_NUMBER: _ClassVar[int]
    WHITELISTED_FIELD_NUMBER: _ClassVar[int]
    HIDESTORY_FIELD_NUMBER: _ClassVar[int]
    STORYSENDMODE_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    masterKey: bytes
    whitelisted: bool
    hideStory: bool
    storySendMode: Group.StorySendMode
    snapshot: Group.GroupSnapshot
    def __init__(self, masterKey: _Optional[bytes] = ..., whitelisted: bool = ..., hideStory: bool = ..., storySendMode: _Optional[_Union[Group.StorySendMode, str]] = ..., snapshot: _Optional[_Union[Group.GroupSnapshot, _Mapping]] = ...) -> None: ...

class Self(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ReleaseNotes(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class Chat(_message.Message):
    __slots__ = ("id", "recipientId", "archived", "pinnedOrder", "expirationTimerMs", "muteUntilMs", "markedUnread", "dontNotifyForMentionsIfMuted", "style")
    ID_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    PINNEDORDER_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONTIMERMS_FIELD_NUMBER: _ClassVar[int]
    MUTEUNTILMS_FIELD_NUMBER: _ClassVar[int]
    MARKEDUNREAD_FIELD_NUMBER: _ClassVar[int]
    DONTNOTIFYFORMENTIONSIFMUTED_FIELD_NUMBER: _ClassVar[int]
    STYLE_FIELD_NUMBER: _ClassVar[int]
    id: int
    recipientId: int
    archived: bool
    pinnedOrder: int
    expirationTimerMs: int
    muteUntilMs: int
    markedUnread: bool
    dontNotifyForMentionsIfMuted: bool
    style: ChatStyle
    def __init__(self, id: _Optional[int] = ..., recipientId: _Optional[int] = ..., archived: bool = ..., pinnedOrder: _Optional[int] = ..., expirationTimerMs: _Optional[int] = ..., muteUntilMs: _Optional[int] = ..., markedUnread: bool = ..., dontNotifyForMentionsIfMuted: bool = ..., style: _Optional[_Union[ChatStyle, _Mapping]] = ...) -> None: ...

class CallLink(_message.Message):
    __slots__ = ("rootKey", "adminKey", "name", "restrictions", "expirationMs")
    class Restrictions(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[CallLink.Restrictions]
        NONE: _ClassVar[CallLink.Restrictions]
        ADMIN_APPROVAL: _ClassVar[CallLink.Restrictions]
    UNKNOWN: CallLink.Restrictions
    NONE: CallLink.Restrictions
    ADMIN_APPROVAL: CallLink.Restrictions
    ROOTKEY_FIELD_NUMBER: _ClassVar[int]
    ADMINKEY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    RESTRICTIONS_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONMS_FIELD_NUMBER: _ClassVar[int]
    rootKey: bytes
    adminKey: bytes
    name: str
    restrictions: CallLink.Restrictions
    expirationMs: int
    def __init__(self, rootKey: _Optional[bytes] = ..., adminKey: _Optional[bytes] = ..., name: _Optional[str] = ..., restrictions: _Optional[_Union[CallLink.Restrictions, str]] = ..., expirationMs: _Optional[int] = ...) -> None: ...

class AdHocCall(_message.Message):
    __slots__ = ("callId", "recipientId", "state", "callTimestamp")
    class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_STATE: _ClassVar[AdHocCall.State]
        GENERIC: _ClassVar[AdHocCall.State]
    UNKNOWN_STATE: AdHocCall.State
    GENERIC: AdHocCall.State
    CALLID_FIELD_NUMBER: _ClassVar[int]
    RECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CALLTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    callId: int
    recipientId: int
    state: AdHocCall.State
    callTimestamp: int
    def __init__(self, callId: _Optional[int] = ..., recipientId: _Optional[int] = ..., state: _Optional[_Union[AdHocCall.State, str]] = ..., callTimestamp: _Optional[int] = ...) -> None: ...

class DistributionListItem(_message.Message):
    __slots__ = ("distributionId", "deletionTimestamp", "distributionList")
    DISTRIBUTIONID_FIELD_NUMBER: _ClassVar[int]
    DELETIONTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    DISTRIBUTIONLIST_FIELD_NUMBER: _ClassVar[int]
    distributionId: bytes
    deletionTimestamp: int
    distributionList: DistributionList
    def __init__(self, distributionId: _Optional[bytes] = ..., deletionTimestamp: _Optional[int] = ..., distributionList: _Optional[_Union[DistributionList, _Mapping]] = ...) -> None: ...

class DistributionList(_message.Message):
    __slots__ = ("name", "allowReplies", "privacyMode", "memberRecipientIds")
    class PrivacyMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[DistributionList.PrivacyMode]
        ONLY_WITH: _ClassVar[DistributionList.PrivacyMode]
        ALL_EXCEPT: _ClassVar[DistributionList.PrivacyMode]
        ALL: _ClassVar[DistributionList.PrivacyMode]
    UNKNOWN: DistributionList.PrivacyMode
    ONLY_WITH: DistributionList.PrivacyMode
    ALL_EXCEPT: DistributionList.PrivacyMode
    ALL: DistributionList.PrivacyMode
    NAME_FIELD_NUMBER: _ClassVar[int]
    ALLOWREPLIES_FIELD_NUMBER: _ClassVar[int]
    PRIVACYMODE_FIELD_NUMBER: _ClassVar[int]
    MEMBERRECIPIENTIDS_FIELD_NUMBER: _ClassVar[int]
    name: str
    allowReplies: bool
    privacyMode: DistributionList.PrivacyMode
    memberRecipientIds: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, name: _Optional[str] = ..., allowReplies: bool = ..., privacyMode: _Optional[_Union[DistributionList.PrivacyMode, str]] = ..., memberRecipientIds: _Optional[_Iterable[int]] = ...) -> None: ...

class ChatItem(_message.Message):
    __slots__ = ("chatId", "authorId", "dateSent", "expireStartDate", "expiresInMs", "revisions", "sms", "incoming", "outgoing", "directionless", "standardMessage", "contactMessage", "stickerMessage", "remoteDeletedMessage", "updateMessage", "paymentNotification", "giftBadge")
    class IncomingMessageDetails(_message.Message):
        __slots__ = ("dateReceived", "dateServerSent", "read", "sealedSender")
        DATERECEIVED_FIELD_NUMBER: _ClassVar[int]
        DATESERVERSENT_FIELD_NUMBER: _ClassVar[int]
        READ_FIELD_NUMBER: _ClassVar[int]
        SEALEDSENDER_FIELD_NUMBER: _ClassVar[int]
        dateReceived: int
        dateServerSent: int
        read: bool
        sealedSender: bool
        def __init__(self, dateReceived: _Optional[int] = ..., dateServerSent: _Optional[int] = ..., read: bool = ..., sealedSender: bool = ...) -> None: ...
    class OutgoingMessageDetails(_message.Message):
        __slots__ = ("sendStatus",)
        SENDSTATUS_FIELD_NUMBER: _ClassVar[int]
        sendStatus: _containers.RepeatedCompositeFieldContainer[SendStatus]
        def __init__(self, sendStatus: _Optional[_Iterable[_Union[SendStatus, _Mapping]]] = ...) -> None: ...
    class DirectionlessMessageDetails(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    CHATID_FIELD_NUMBER: _ClassVar[int]
    AUTHORID_FIELD_NUMBER: _ClassVar[int]
    DATESENT_FIELD_NUMBER: _ClassVar[int]
    EXPIRESTARTDATE_FIELD_NUMBER: _ClassVar[int]
    EXPIRESINMS_FIELD_NUMBER: _ClassVar[int]
    REVISIONS_FIELD_NUMBER: _ClassVar[int]
    SMS_FIELD_NUMBER: _ClassVar[int]
    INCOMING_FIELD_NUMBER: _ClassVar[int]
    OUTGOING_FIELD_NUMBER: _ClassVar[int]
    DIRECTIONLESS_FIELD_NUMBER: _ClassVar[int]
    STANDARDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    CONTACTMESSAGE_FIELD_NUMBER: _ClassVar[int]
    STICKERMESSAGE_FIELD_NUMBER: _ClassVar[int]
    REMOTEDELETEDMESSAGE_FIELD_NUMBER: _ClassVar[int]
    UPDATEMESSAGE_FIELD_NUMBER: _ClassVar[int]
    PAYMENTNOTIFICATION_FIELD_NUMBER: _ClassVar[int]
    GIFTBADGE_FIELD_NUMBER: _ClassVar[int]
    chatId: int
    authorId: int
    dateSent: int
    expireStartDate: int
    expiresInMs: int
    revisions: _containers.RepeatedCompositeFieldContainer[ChatItem]
    sms: bool
    incoming: ChatItem.IncomingMessageDetails
    outgoing: ChatItem.OutgoingMessageDetails
    directionless: ChatItem.DirectionlessMessageDetails
    standardMessage: StandardMessage
    contactMessage: ContactMessage
    stickerMessage: StickerMessage
    remoteDeletedMessage: RemoteDeletedMessage
    updateMessage: ChatUpdateMessage
    paymentNotification: PaymentNotification
    giftBadge: GiftBadge
    def __init__(self, chatId: _Optional[int] = ..., authorId: _Optional[int] = ..., dateSent: _Optional[int] = ..., expireStartDate: _Optional[int] = ..., expiresInMs: _Optional[int] = ..., revisions: _Optional[_Iterable[_Union[ChatItem, _Mapping]]] = ..., sms: bool = ..., incoming: _Optional[_Union[ChatItem.IncomingMessageDetails, _Mapping]] = ..., outgoing: _Optional[_Union[ChatItem.OutgoingMessageDetails, _Mapping]] = ..., directionless: _Optional[_Union[ChatItem.DirectionlessMessageDetails, _Mapping]] = ..., standardMessage: _Optional[_Union[StandardMessage, _Mapping]] = ..., contactMessage: _Optional[_Union[ContactMessage, _Mapping]] = ..., stickerMessage: _Optional[_Union[StickerMessage, _Mapping]] = ..., remoteDeletedMessage: _Optional[_Union[RemoteDeletedMessage, _Mapping]] = ..., updateMessage: _Optional[_Union[ChatUpdateMessage, _Mapping]] = ..., paymentNotification: _Optional[_Union[PaymentNotification, _Mapping]] = ..., giftBadge: _Optional[_Union[GiftBadge, _Mapping]] = ...) -> None: ...

class SendStatus(_message.Message):
    __slots__ = ("recipientId", "deliveryStatus", "networkFailure", "identityKeyMismatch", "sealedSender", "lastStatusUpdateTimestamp")
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[SendStatus.Status]
        FAILED: _ClassVar[SendStatus.Status]
        PENDING: _ClassVar[SendStatus.Status]
        SENT: _ClassVar[SendStatus.Status]
        DELIVERED: _ClassVar[SendStatus.Status]
        READ: _ClassVar[SendStatus.Status]
        VIEWED: _ClassVar[SendStatus.Status]
        SKIPPED: _ClassVar[SendStatus.Status]
    UNKNOWN: SendStatus.Status
    FAILED: SendStatus.Status
    PENDING: SendStatus.Status
    SENT: SendStatus.Status
    DELIVERED: SendStatus.Status
    READ: SendStatus.Status
    VIEWED: SendStatus.Status
    SKIPPED: SendStatus.Status
    RECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    DELIVERYSTATUS_FIELD_NUMBER: _ClassVar[int]
    NETWORKFAILURE_FIELD_NUMBER: _ClassVar[int]
    IDENTITYKEYMISMATCH_FIELD_NUMBER: _ClassVar[int]
    SEALEDSENDER_FIELD_NUMBER: _ClassVar[int]
    LASTSTATUSUPDATETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    recipientId: int
    deliveryStatus: SendStatus.Status
    networkFailure: bool
    identityKeyMismatch: bool
    sealedSender: bool
    lastStatusUpdateTimestamp: int
    def __init__(self, recipientId: _Optional[int] = ..., deliveryStatus: _Optional[_Union[SendStatus.Status, str]] = ..., networkFailure: bool = ..., identityKeyMismatch: bool = ..., sealedSender: bool = ..., lastStatusUpdateTimestamp: _Optional[int] = ...) -> None: ...

class Text(_message.Message):
    __slots__ = ("body", "bodyRanges")
    BODY_FIELD_NUMBER: _ClassVar[int]
    BODYRANGES_FIELD_NUMBER: _ClassVar[int]
    body: str
    bodyRanges: _containers.RepeatedCompositeFieldContainer[BodyRange]
    def __init__(self, body: _Optional[str] = ..., bodyRanges: _Optional[_Iterable[_Union[BodyRange, _Mapping]]] = ...) -> None: ...

class StandardMessage(_message.Message):
    __slots__ = ("quote", "text", "attachments", "linkPreview", "longText", "reactions")
    QUOTE_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    LINKPREVIEW_FIELD_NUMBER: _ClassVar[int]
    LONGTEXT_FIELD_NUMBER: _ClassVar[int]
    REACTIONS_FIELD_NUMBER: _ClassVar[int]
    quote: Quote
    text: Text
    attachments: _containers.RepeatedCompositeFieldContainer[MessageAttachment]
    linkPreview: _containers.RepeatedCompositeFieldContainer[LinkPreview]
    longText: FilePointer
    reactions: _containers.RepeatedCompositeFieldContainer[Reaction]
    def __init__(self, quote: _Optional[_Union[Quote, _Mapping]] = ..., text: _Optional[_Union[Text, _Mapping]] = ..., attachments: _Optional[_Iterable[_Union[MessageAttachment, _Mapping]]] = ..., linkPreview: _Optional[_Iterable[_Union[LinkPreview, _Mapping]]] = ..., longText: _Optional[_Union[FilePointer, _Mapping]] = ..., reactions: _Optional[_Iterable[_Union[Reaction, _Mapping]]] = ...) -> None: ...

class ContactMessage(_message.Message):
    __slots__ = ("contact", "reactions")
    CONTACT_FIELD_NUMBER: _ClassVar[int]
    REACTIONS_FIELD_NUMBER: _ClassVar[int]
    contact: _containers.RepeatedCompositeFieldContainer[ContactAttachment]
    reactions: _containers.RepeatedCompositeFieldContainer[Reaction]
    def __init__(self, contact: _Optional[_Iterable[_Union[ContactAttachment, _Mapping]]] = ..., reactions: _Optional[_Iterable[_Union[Reaction, _Mapping]]] = ...) -> None: ...

class PaymentNotification(_message.Message):
    __slots__ = ("amountMob", "feeMob", "note", "transactionDetails")
    class TransactionDetails(_message.Message):
        __slots__ = ("transaction", "failedTransaction")
        class MobileCoinTxoIdentification(_message.Message):
            __slots__ = ("publicKey", "keyImages")
            PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
            KEYIMAGES_FIELD_NUMBER: _ClassVar[int]
            publicKey: _containers.RepeatedScalarFieldContainer[bytes]
            keyImages: _containers.RepeatedScalarFieldContainer[bytes]
            def __init__(self, publicKey: _Optional[_Iterable[bytes]] = ..., keyImages: _Optional[_Iterable[bytes]] = ...) -> None: ...
        class FailedTransaction(_message.Message):
            __slots__ = ("reason",)
            class FailureReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                GENERIC: _ClassVar[PaymentNotification.TransactionDetails.FailedTransaction.FailureReason]
                NETWORK: _ClassVar[PaymentNotification.TransactionDetails.FailedTransaction.FailureReason]
                INSUFFICIENT_FUNDS: _ClassVar[PaymentNotification.TransactionDetails.FailedTransaction.FailureReason]
            GENERIC: PaymentNotification.TransactionDetails.FailedTransaction.FailureReason
            NETWORK: PaymentNotification.TransactionDetails.FailedTransaction.FailureReason
            INSUFFICIENT_FUNDS: PaymentNotification.TransactionDetails.FailedTransaction.FailureReason
            REASON_FIELD_NUMBER: _ClassVar[int]
            reason: PaymentNotification.TransactionDetails.FailedTransaction.FailureReason
            def __init__(self, reason: _Optional[_Union[PaymentNotification.TransactionDetails.FailedTransaction.FailureReason, str]] = ...) -> None: ...
        class Transaction(_message.Message):
            __slots__ = ("status", "mobileCoinIdentification", "timestamp", "blockIndex", "blockTimestamp", "transaction", "receipt")
            class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                INITIAL: _ClassVar[PaymentNotification.TransactionDetails.Transaction.Status]
                SUBMITTED: _ClassVar[PaymentNotification.TransactionDetails.Transaction.Status]
                SUCCESSFUL: _ClassVar[PaymentNotification.TransactionDetails.Transaction.Status]
            INITIAL: PaymentNotification.TransactionDetails.Transaction.Status
            SUBMITTED: PaymentNotification.TransactionDetails.Transaction.Status
            SUCCESSFUL: PaymentNotification.TransactionDetails.Transaction.Status
            STATUS_FIELD_NUMBER: _ClassVar[int]
            MOBILECOINIDENTIFICATION_FIELD_NUMBER: _ClassVar[int]
            TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
            BLOCKINDEX_FIELD_NUMBER: _ClassVar[int]
            BLOCKTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
            TRANSACTION_FIELD_NUMBER: _ClassVar[int]
            RECEIPT_FIELD_NUMBER: _ClassVar[int]
            status: PaymentNotification.TransactionDetails.Transaction.Status
            mobileCoinIdentification: PaymentNotification.TransactionDetails.MobileCoinTxoIdentification
            timestamp: int
            blockIndex: int
            blockTimestamp: int
            transaction: bytes
            receipt: bytes
            def __init__(self, status: _Optional[_Union[PaymentNotification.TransactionDetails.Transaction.Status, str]] = ..., mobileCoinIdentification: _Optional[_Union[PaymentNotification.TransactionDetails.MobileCoinTxoIdentification, _Mapping]] = ..., timestamp: _Optional[int] = ..., blockIndex: _Optional[int] = ..., blockTimestamp: _Optional[int] = ..., transaction: _Optional[bytes] = ..., receipt: _Optional[bytes] = ...) -> None: ...
        TRANSACTION_FIELD_NUMBER: _ClassVar[int]
        FAILEDTRANSACTION_FIELD_NUMBER: _ClassVar[int]
        transaction: PaymentNotification.TransactionDetails.Transaction
        failedTransaction: PaymentNotification.TransactionDetails.FailedTransaction
        def __init__(self, transaction: _Optional[_Union[PaymentNotification.TransactionDetails.Transaction, _Mapping]] = ..., failedTransaction: _Optional[_Union[PaymentNotification.TransactionDetails.FailedTransaction, _Mapping]] = ...) -> None: ...
    AMOUNTMOB_FIELD_NUMBER: _ClassVar[int]
    FEEMOB_FIELD_NUMBER: _ClassVar[int]
    NOTE_FIELD_NUMBER: _ClassVar[int]
    TRANSACTIONDETAILS_FIELD_NUMBER: _ClassVar[int]
    amountMob: str
    feeMob: str
    note: str
    transactionDetails: PaymentNotification.TransactionDetails
    def __init__(self, amountMob: _Optional[str] = ..., feeMob: _Optional[str] = ..., note: _Optional[str] = ..., transactionDetails: _Optional[_Union[PaymentNotification.TransactionDetails, _Mapping]] = ...) -> None: ...

class GiftBadge(_message.Message):
    __slots__ = ("receiptCredentialPresentation", "state")
    class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNOPENED: _ClassVar[GiftBadge.State]
        OPENED: _ClassVar[GiftBadge.State]
        REDEEMED: _ClassVar[GiftBadge.State]
        FAILED: _ClassVar[GiftBadge.State]
    UNOPENED: GiftBadge.State
    OPENED: GiftBadge.State
    REDEEMED: GiftBadge.State
    FAILED: GiftBadge.State
    RECEIPTCREDENTIALPRESENTATION_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    receiptCredentialPresentation: bytes
    state: GiftBadge.State
    def __init__(self, receiptCredentialPresentation: _Optional[bytes] = ..., state: _Optional[_Union[GiftBadge.State, str]] = ...) -> None: ...

class ContactAttachment(_message.Message):
    __slots__ = ("name", "number", "email", "address", "avatar", "organization")
    class Name(_message.Message):
        __slots__ = ("givenName", "familyName", "prefix", "suffix", "middleName", "displayName")
        GIVENNAME_FIELD_NUMBER: _ClassVar[int]
        FAMILYNAME_FIELD_NUMBER: _ClassVar[int]
        PREFIX_FIELD_NUMBER: _ClassVar[int]
        SUFFIX_FIELD_NUMBER: _ClassVar[int]
        MIDDLENAME_FIELD_NUMBER: _ClassVar[int]
        DISPLAYNAME_FIELD_NUMBER: _ClassVar[int]
        givenName: str
        familyName: str
        prefix: str
        suffix: str
        middleName: str
        displayName: str
        def __init__(self, givenName: _Optional[str] = ..., familyName: _Optional[str] = ..., prefix: _Optional[str] = ..., suffix: _Optional[str] = ..., middleName: _Optional[str] = ..., displayName: _Optional[str] = ...) -> None: ...
    class Phone(_message.Message):
        __slots__ = ("value", "type", "label")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[ContactAttachment.Phone.Type]
            HOME: _ClassVar[ContactAttachment.Phone.Type]
            MOBILE: _ClassVar[ContactAttachment.Phone.Type]
            WORK: _ClassVar[ContactAttachment.Phone.Type]
            CUSTOM: _ClassVar[ContactAttachment.Phone.Type]
        UNKNOWN: ContactAttachment.Phone.Type
        HOME: ContactAttachment.Phone.Type
        MOBILE: ContactAttachment.Phone.Type
        WORK: ContactAttachment.Phone.Type
        CUSTOM: ContactAttachment.Phone.Type
        VALUE_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        LABEL_FIELD_NUMBER: _ClassVar[int]
        value: str
        type: ContactAttachment.Phone.Type
        label: str
        def __init__(self, value: _Optional[str] = ..., type: _Optional[_Union[ContactAttachment.Phone.Type, str]] = ..., label: _Optional[str] = ...) -> None: ...
    class Email(_message.Message):
        __slots__ = ("value", "type", "label")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[ContactAttachment.Email.Type]
            HOME: _ClassVar[ContactAttachment.Email.Type]
            MOBILE: _ClassVar[ContactAttachment.Email.Type]
            WORK: _ClassVar[ContactAttachment.Email.Type]
            CUSTOM: _ClassVar[ContactAttachment.Email.Type]
        UNKNOWN: ContactAttachment.Email.Type
        HOME: ContactAttachment.Email.Type
        MOBILE: ContactAttachment.Email.Type
        WORK: ContactAttachment.Email.Type
        CUSTOM: ContactAttachment.Email.Type
        VALUE_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        LABEL_FIELD_NUMBER: _ClassVar[int]
        value: str
        type: ContactAttachment.Email.Type
        label: str
        def __init__(self, value: _Optional[str] = ..., type: _Optional[_Union[ContactAttachment.Email.Type, str]] = ..., label: _Optional[str] = ...) -> None: ...
    class PostalAddress(_message.Message):
        __slots__ = ("type", "label", "street", "pobox", "neighborhood", "city", "region", "postcode", "country")
        class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN: _ClassVar[ContactAttachment.PostalAddress.Type]
            HOME: _ClassVar[ContactAttachment.PostalAddress.Type]
            WORK: _ClassVar[ContactAttachment.PostalAddress.Type]
            CUSTOM: _ClassVar[ContactAttachment.PostalAddress.Type]
        UNKNOWN: ContactAttachment.PostalAddress.Type
        HOME: ContactAttachment.PostalAddress.Type
        WORK: ContactAttachment.PostalAddress.Type
        CUSTOM: ContactAttachment.PostalAddress.Type
        TYPE_FIELD_NUMBER: _ClassVar[int]
        LABEL_FIELD_NUMBER: _ClassVar[int]
        STREET_FIELD_NUMBER: _ClassVar[int]
        POBOX_FIELD_NUMBER: _ClassVar[int]
        NEIGHBORHOOD_FIELD_NUMBER: _ClassVar[int]
        CITY_FIELD_NUMBER: _ClassVar[int]
        REGION_FIELD_NUMBER: _ClassVar[int]
        POSTCODE_FIELD_NUMBER: _ClassVar[int]
        COUNTRY_FIELD_NUMBER: _ClassVar[int]
        type: ContactAttachment.PostalAddress.Type
        label: str
        street: str
        pobox: str
        neighborhood: str
        city: str
        region: str
        postcode: str
        country: str
        def __init__(self, type: _Optional[_Union[ContactAttachment.PostalAddress.Type, str]] = ..., label: _Optional[str] = ..., street: _Optional[str] = ..., pobox: _Optional[str] = ..., neighborhood: _Optional[str] = ..., city: _Optional[str] = ..., region: _Optional[str] = ..., postcode: _Optional[str] = ..., country: _Optional[str] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    NUMBER_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    name: ContactAttachment.Name
    number: _containers.RepeatedCompositeFieldContainer[ContactAttachment.Phone]
    email: _containers.RepeatedCompositeFieldContainer[ContactAttachment.Email]
    address: _containers.RepeatedCompositeFieldContainer[ContactAttachment.PostalAddress]
    avatar: FilePointer
    organization: str
    def __init__(self, name: _Optional[_Union[ContactAttachment.Name, _Mapping]] = ..., number: _Optional[_Iterable[_Union[ContactAttachment.Phone, _Mapping]]] = ..., email: _Optional[_Iterable[_Union[ContactAttachment.Email, _Mapping]]] = ..., address: _Optional[_Iterable[_Union[ContactAttachment.PostalAddress, _Mapping]]] = ..., avatar: _Optional[_Union[FilePointer, _Mapping]] = ..., organization: _Optional[str] = ...) -> None: ...

class StickerMessage(_message.Message):
    __slots__ = ("sticker", "reactions")
    STICKER_FIELD_NUMBER: _ClassVar[int]
    REACTIONS_FIELD_NUMBER: _ClassVar[int]
    sticker: Sticker
    reactions: _containers.RepeatedCompositeFieldContainer[Reaction]
    def __init__(self, sticker: _Optional[_Union[Sticker, _Mapping]] = ..., reactions: _Optional[_Iterable[_Union[Reaction, _Mapping]]] = ...) -> None: ...

class RemoteDeletedMessage(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class Sticker(_message.Message):
    __slots__ = ("packId", "packKey", "stickerId", "emoji", "data")
    PACKID_FIELD_NUMBER: _ClassVar[int]
    PACKKEY_FIELD_NUMBER: _ClassVar[int]
    STICKERID_FIELD_NUMBER: _ClassVar[int]
    EMOJI_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    packId: bytes
    packKey: bytes
    stickerId: int
    emoji: str
    data: FilePointer
    def __init__(self, packId: _Optional[bytes] = ..., packKey: _Optional[bytes] = ..., stickerId: _Optional[int] = ..., emoji: _Optional[str] = ..., data: _Optional[_Union[FilePointer, _Mapping]] = ...) -> None: ...

class LinkPreview(_message.Message):
    __slots__ = ("url", "title", "image", "description", "date")
    URL_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DATE_FIELD_NUMBER: _ClassVar[int]
    url: str
    title: str
    image: FilePointer
    description: str
    date: int
    def __init__(self, url: _Optional[str] = ..., title: _Optional[str] = ..., image: _Optional[_Union[FilePointer, _Mapping]] = ..., description: _Optional[str] = ..., date: _Optional[int] = ...) -> None: ...

class MessageAttachment(_message.Message):
    __slots__ = ("pointer", "flag", "wasDownloaded", "clientUuid")
    class Flag(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[MessageAttachment.Flag]
        VOICE_MESSAGE: _ClassVar[MessageAttachment.Flag]
        BORDERLESS: _ClassVar[MessageAttachment.Flag]
        GIF: _ClassVar[MessageAttachment.Flag]
    NONE: MessageAttachment.Flag
    VOICE_MESSAGE: MessageAttachment.Flag
    BORDERLESS: MessageAttachment.Flag
    GIF: MessageAttachment.Flag
    POINTER_FIELD_NUMBER: _ClassVar[int]
    FLAG_FIELD_NUMBER: _ClassVar[int]
    WASDOWNLOADED_FIELD_NUMBER: _ClassVar[int]
    CLIENTUUID_FIELD_NUMBER: _ClassVar[int]
    pointer: FilePointer
    flag: MessageAttachment.Flag
    wasDownloaded: bool
    clientUuid: bytes
    def __init__(self, pointer: _Optional[_Union[FilePointer, _Mapping]] = ..., flag: _Optional[_Union[MessageAttachment.Flag, str]] = ..., wasDownloaded: bool = ..., clientUuid: _Optional[bytes] = ...) -> None: ...

class FilePointer(_message.Message):
    __slots__ = ("backupLocator", "attachmentLocator", "invalidAttachmentLocator", "contentType", "incrementalMac", "incrementalMacChunkSize", "fileName", "width", "height", "caption", "blurHash")
    class BackupLocator(_message.Message):
        __slots__ = ("mediaName", "cdnNumber", "key", "digest", "size", "transitCdnKey", "transitCdnNumber")
        MEDIANAME_FIELD_NUMBER: _ClassVar[int]
        CDNNUMBER_FIELD_NUMBER: _ClassVar[int]
        KEY_FIELD_NUMBER: _ClassVar[int]
        DIGEST_FIELD_NUMBER: _ClassVar[int]
        SIZE_FIELD_NUMBER: _ClassVar[int]
        TRANSITCDNKEY_FIELD_NUMBER: _ClassVar[int]
        TRANSITCDNNUMBER_FIELD_NUMBER: _ClassVar[int]
        mediaName: str
        cdnNumber: int
        key: bytes
        digest: bytes
        size: int
        transitCdnKey: str
        transitCdnNumber: int
        def __init__(self, mediaName: _Optional[str] = ..., cdnNumber: _Optional[int] = ..., key: _Optional[bytes] = ..., digest: _Optional[bytes] = ..., size: _Optional[int] = ..., transitCdnKey: _Optional[str] = ..., transitCdnNumber: _Optional[int] = ...) -> None: ...
    class AttachmentLocator(_message.Message):
        __slots__ = ("cdnKey", "cdnNumber", "uploadTimestamp", "key", "digest", "size")
        CDNKEY_FIELD_NUMBER: _ClassVar[int]
        CDNNUMBER_FIELD_NUMBER: _ClassVar[int]
        UPLOADTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
        KEY_FIELD_NUMBER: _ClassVar[int]
        DIGEST_FIELD_NUMBER: _ClassVar[int]
        SIZE_FIELD_NUMBER: _ClassVar[int]
        cdnKey: str
        cdnNumber: int
        uploadTimestamp: int
        key: bytes
        digest: bytes
        size: int
        def __init__(self, cdnKey: _Optional[str] = ..., cdnNumber: _Optional[int] = ..., uploadTimestamp: _Optional[int] = ..., key: _Optional[bytes] = ..., digest: _Optional[bytes] = ..., size: _Optional[int] = ...) -> None: ...
    class InvalidAttachmentLocator(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    BACKUPLOCATOR_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTLOCATOR_FIELD_NUMBER: _ClassVar[int]
    INVALIDATTACHMENTLOCATOR_FIELD_NUMBER: _ClassVar[int]
    CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
    INCREMENTALMAC_FIELD_NUMBER: _ClassVar[int]
    INCREMENTALMACCHUNKSIZE_FIELD_NUMBER: _ClassVar[int]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    BLURHASH_FIELD_NUMBER: _ClassVar[int]
    backupLocator: FilePointer.BackupLocator
    attachmentLocator: FilePointer.AttachmentLocator
    invalidAttachmentLocator: FilePointer.InvalidAttachmentLocator
    contentType: str
    incrementalMac: bytes
    incrementalMacChunkSize: int
    fileName: str
    width: int
    height: int
    caption: str
    blurHash: str
    def __init__(self, backupLocator: _Optional[_Union[FilePointer.BackupLocator, _Mapping]] = ..., attachmentLocator: _Optional[_Union[FilePointer.AttachmentLocator, _Mapping]] = ..., invalidAttachmentLocator: _Optional[_Union[FilePointer.InvalidAttachmentLocator, _Mapping]] = ..., contentType: _Optional[str] = ..., incrementalMac: _Optional[bytes] = ..., incrementalMacChunkSize: _Optional[int] = ..., fileName: _Optional[str] = ..., width: _Optional[int] = ..., height: _Optional[int] = ..., caption: _Optional[str] = ..., blurHash: _Optional[str] = ...) -> None: ...

class Quote(_message.Message):
    __slots__ = ("targetSentTimestamp", "authorId", "text", "attachments", "bodyRanges", "type")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[Quote.Type]
        NORMAL: _ClassVar[Quote.Type]
        GIFTBADGE: _ClassVar[Quote.Type]
    UNKNOWN: Quote.Type
    NORMAL: Quote.Type
    GIFTBADGE: Quote.Type
    class QuotedAttachment(_message.Message):
        __slots__ = ("contentType", "fileName", "thumbnail")
        CONTENTTYPE_FIELD_NUMBER: _ClassVar[int]
        FILENAME_FIELD_NUMBER: _ClassVar[int]
        THUMBNAIL_FIELD_NUMBER: _ClassVar[int]
        contentType: str
        fileName: str
        thumbnail: MessageAttachment
        def __init__(self, contentType: _Optional[str] = ..., fileName: _Optional[str] = ..., thumbnail: _Optional[_Union[MessageAttachment, _Mapping]] = ...) -> None: ...
    TARGETSENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    AUTHORID_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENTS_FIELD_NUMBER: _ClassVar[int]
    BODYRANGES_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    targetSentTimestamp: int
    authorId: int
    text: str
    attachments: _containers.RepeatedCompositeFieldContainer[Quote.QuotedAttachment]
    bodyRanges: _containers.RepeatedCompositeFieldContainer[BodyRange]
    type: Quote.Type
    def __init__(self, targetSentTimestamp: _Optional[int] = ..., authorId: _Optional[int] = ..., text: _Optional[str] = ..., attachments: _Optional[_Iterable[_Union[Quote.QuotedAttachment, _Mapping]]] = ..., bodyRanges: _Optional[_Iterable[_Union[BodyRange, _Mapping]]] = ..., type: _Optional[_Union[Quote.Type, str]] = ...) -> None: ...

class BodyRange(_message.Message):
    __slots__ = ("start", "length", "mentionAci", "style")
    class Style(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[BodyRange.Style]
        BOLD: _ClassVar[BodyRange.Style]
        ITALIC: _ClassVar[BodyRange.Style]
        SPOILER: _ClassVar[BodyRange.Style]
        STRIKETHROUGH: _ClassVar[BodyRange.Style]
        MONOSPACE: _ClassVar[BodyRange.Style]
    NONE: BodyRange.Style
    BOLD: BodyRange.Style
    ITALIC: BodyRange.Style
    SPOILER: BodyRange.Style
    STRIKETHROUGH: BodyRange.Style
    MONOSPACE: BodyRange.Style
    START_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    MENTIONACI_FIELD_NUMBER: _ClassVar[int]
    STYLE_FIELD_NUMBER: _ClassVar[int]
    start: int
    length: int
    mentionAci: bytes
    style: BodyRange.Style
    def __init__(self, start: _Optional[int] = ..., length: _Optional[int] = ..., mentionAci: _Optional[bytes] = ..., style: _Optional[_Union[BodyRange.Style, str]] = ...) -> None: ...

class Reaction(_message.Message):
    __slots__ = ("emoji", "authorId", "sentTimestamp", "receivedTimestamp", "sortOrder")
    EMOJI_FIELD_NUMBER: _ClassVar[int]
    AUTHORID_FIELD_NUMBER: _ClassVar[int]
    SENTTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    RECEIVEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SORTORDER_FIELD_NUMBER: _ClassVar[int]
    emoji: str
    authorId: int
    sentTimestamp: int
    receivedTimestamp: int
    sortOrder: int
    def __init__(self, emoji: _Optional[str] = ..., authorId: _Optional[int] = ..., sentTimestamp: _Optional[int] = ..., receivedTimestamp: _Optional[int] = ..., sortOrder: _Optional[int] = ...) -> None: ...

class ChatUpdateMessage(_message.Message):
    __slots__ = ("simpleUpdate", "groupChange", "expirationTimerChange", "profileChange", "threadMerge", "sessionSwitchover", "individualCall", "groupCall", "learnedProfileChange")
    SIMPLEUPDATE_FIELD_NUMBER: _ClassVar[int]
    GROUPCHANGE_FIELD_NUMBER: _ClassVar[int]
    EXPIRATIONTIMERCHANGE_FIELD_NUMBER: _ClassVar[int]
    PROFILECHANGE_FIELD_NUMBER: _ClassVar[int]
    THREADMERGE_FIELD_NUMBER: _ClassVar[int]
    SESSIONSWITCHOVER_FIELD_NUMBER: _ClassVar[int]
    INDIVIDUALCALL_FIELD_NUMBER: _ClassVar[int]
    GROUPCALL_FIELD_NUMBER: _ClassVar[int]
    LEARNEDPROFILECHANGE_FIELD_NUMBER: _ClassVar[int]
    simpleUpdate: SimpleChatUpdate
    groupChange: GroupChangeChatUpdate
    expirationTimerChange: ExpirationTimerChatUpdate
    profileChange: ProfileChangeChatUpdate
    threadMerge: ThreadMergeChatUpdate
    sessionSwitchover: SessionSwitchoverChatUpdate
    individualCall: IndividualCall
    groupCall: GroupCall
    learnedProfileChange: LearnedProfileChatUpdate
    def __init__(self, simpleUpdate: _Optional[_Union[SimpleChatUpdate, _Mapping]] = ..., groupChange: _Optional[_Union[GroupChangeChatUpdate, _Mapping]] = ..., expirationTimerChange: _Optional[_Union[ExpirationTimerChatUpdate, _Mapping]] = ..., profileChange: _Optional[_Union[ProfileChangeChatUpdate, _Mapping]] = ..., threadMerge: _Optional[_Union[ThreadMergeChatUpdate, _Mapping]] = ..., sessionSwitchover: _Optional[_Union[SessionSwitchoverChatUpdate, _Mapping]] = ..., individualCall: _Optional[_Union[IndividualCall, _Mapping]] = ..., groupCall: _Optional[_Union[GroupCall, _Mapping]] = ..., learnedProfileChange: _Optional[_Union[LearnedProfileChatUpdate, _Mapping]] = ...) -> None: ...

class IndividualCall(_message.Message):
    __slots__ = ("callId", "type", "direction", "state", "startedCallTimestamp")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_TYPE: _ClassVar[IndividualCall.Type]
        AUDIO_CALL: _ClassVar[IndividualCall.Type]
        VIDEO_CALL: _ClassVar[IndividualCall.Type]
    UNKNOWN_TYPE: IndividualCall.Type
    AUDIO_CALL: IndividualCall.Type
    VIDEO_CALL: IndividualCall.Type
    class Direction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_DIRECTION: _ClassVar[IndividualCall.Direction]
        INCOMING: _ClassVar[IndividualCall.Direction]
        OUTGOING: _ClassVar[IndividualCall.Direction]
    UNKNOWN_DIRECTION: IndividualCall.Direction
    INCOMING: IndividualCall.Direction
    OUTGOING: IndividualCall.Direction
    class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_STATE: _ClassVar[IndividualCall.State]
        ACCEPTED: _ClassVar[IndividualCall.State]
        NOT_ACCEPTED: _ClassVar[IndividualCall.State]
        MISSED: _ClassVar[IndividualCall.State]
        MISSED_NOTIFICATION_PROFILE: _ClassVar[IndividualCall.State]
    UNKNOWN_STATE: IndividualCall.State
    ACCEPTED: IndividualCall.State
    NOT_ACCEPTED: IndividualCall.State
    MISSED: IndividualCall.State
    MISSED_NOTIFICATION_PROFILE: IndividualCall.State
    CALLID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    STARTEDCALLTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    callId: int
    type: IndividualCall.Type
    direction: IndividualCall.Direction
    state: IndividualCall.State
    startedCallTimestamp: int
    def __init__(self, callId: _Optional[int] = ..., type: _Optional[_Union[IndividualCall.Type, str]] = ..., direction: _Optional[_Union[IndividualCall.Direction, str]] = ..., state: _Optional[_Union[IndividualCall.State, str]] = ..., startedCallTimestamp: _Optional[int] = ...) -> None: ...

class GroupCall(_message.Message):
    __slots__ = ("callId", "state", "ringerRecipientId", "startedCallRecipientId", "startedCallTimestamp", "endedCallTimestamp")
    class State(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_STATE: _ClassVar[GroupCall.State]
        GENERIC: _ClassVar[GroupCall.State]
        JOINED: _ClassVar[GroupCall.State]
        RINGING: _ClassVar[GroupCall.State]
        ACCEPTED: _ClassVar[GroupCall.State]
        DECLINED: _ClassVar[GroupCall.State]
        MISSED: _ClassVar[GroupCall.State]
        MISSED_NOTIFICATION_PROFILE: _ClassVar[GroupCall.State]
        OUTGOING_RING: _ClassVar[GroupCall.State]
    UNKNOWN_STATE: GroupCall.State
    GENERIC: GroupCall.State
    JOINED: GroupCall.State
    RINGING: GroupCall.State
    ACCEPTED: GroupCall.State
    DECLINED: GroupCall.State
    MISSED: GroupCall.State
    MISSED_NOTIFICATION_PROFILE: GroupCall.State
    OUTGOING_RING: GroupCall.State
    CALLID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    RINGERRECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    STARTEDCALLRECIPIENTID_FIELD_NUMBER: _ClassVar[int]
    STARTEDCALLTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ENDEDCALLTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    callId: int
    state: GroupCall.State
    ringerRecipientId: int
    startedCallRecipientId: int
    startedCallTimestamp: int
    endedCallTimestamp: int
    def __init__(self, callId: _Optional[int] = ..., state: _Optional[_Union[GroupCall.State, str]] = ..., ringerRecipientId: _Optional[int] = ..., startedCallRecipientId: _Optional[int] = ..., startedCallTimestamp: _Optional[int] = ..., endedCallTimestamp: _Optional[int] = ...) -> None: ...

class SimpleChatUpdate(_message.Message):
    __slots__ = ("type",)
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[SimpleChatUpdate.Type]
        JOINED_SIGNAL: _ClassVar[SimpleChatUpdate.Type]
        IDENTITY_UPDATE: _ClassVar[SimpleChatUpdate.Type]
        IDENTITY_VERIFIED: _ClassVar[SimpleChatUpdate.Type]
        IDENTITY_DEFAULT: _ClassVar[SimpleChatUpdate.Type]
        CHANGE_NUMBER: _ClassVar[SimpleChatUpdate.Type]
        RELEASE_CHANNEL_DONATION_REQUEST: _ClassVar[SimpleChatUpdate.Type]
        END_SESSION: _ClassVar[SimpleChatUpdate.Type]
        CHAT_SESSION_REFRESH: _ClassVar[SimpleChatUpdate.Type]
        BAD_DECRYPT: _ClassVar[SimpleChatUpdate.Type]
        PAYMENTS_ACTIVATED: _ClassVar[SimpleChatUpdate.Type]
        PAYMENT_ACTIVATION_REQUEST: _ClassVar[SimpleChatUpdate.Type]
        UNSUPPORTED_PROTOCOL_MESSAGE: _ClassVar[SimpleChatUpdate.Type]
        REPORTED_SPAM: _ClassVar[SimpleChatUpdate.Type]
    UNKNOWN: SimpleChatUpdate.Type
    JOINED_SIGNAL: SimpleChatUpdate.Type
    IDENTITY_UPDATE: SimpleChatUpdate.Type
    IDENTITY_VERIFIED: SimpleChatUpdate.Type
    IDENTITY_DEFAULT: SimpleChatUpdate.Type
    CHANGE_NUMBER: SimpleChatUpdate.Type
    RELEASE_CHANNEL_DONATION_REQUEST: SimpleChatUpdate.Type
    END_SESSION: SimpleChatUpdate.Type
    CHAT_SESSION_REFRESH: SimpleChatUpdate.Type
    BAD_DECRYPT: SimpleChatUpdate.Type
    PAYMENTS_ACTIVATED: SimpleChatUpdate.Type
    PAYMENT_ACTIVATION_REQUEST: SimpleChatUpdate.Type
    UNSUPPORTED_PROTOCOL_MESSAGE: SimpleChatUpdate.Type
    REPORTED_SPAM: SimpleChatUpdate.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    type: SimpleChatUpdate.Type
    def __init__(self, type: _Optional[_Union[SimpleChatUpdate.Type, str]] = ...) -> None: ...

class ExpirationTimerChatUpdate(_message.Message):
    __slots__ = ("expiresInMs",)
    EXPIRESINMS_FIELD_NUMBER: _ClassVar[int]
    expiresInMs: int
    def __init__(self, expiresInMs: _Optional[int] = ...) -> None: ...

class ProfileChangeChatUpdate(_message.Message):
    __slots__ = ("previousName", "newName")
    PREVIOUSNAME_FIELD_NUMBER: _ClassVar[int]
    NEWNAME_FIELD_NUMBER: _ClassVar[int]
    previousName: str
    newName: str
    def __init__(self, previousName: _Optional[str] = ..., newName: _Optional[str] = ...) -> None: ...

class LearnedProfileChatUpdate(_message.Message):
    __slots__ = ("e164", "username")
    E164_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    e164: int
    username: str
    def __init__(self, e164: _Optional[int] = ..., username: _Optional[str] = ...) -> None: ...

class ThreadMergeChatUpdate(_message.Message):
    __slots__ = ("previousE164",)
    PREVIOUSE164_FIELD_NUMBER: _ClassVar[int]
    previousE164: int
    def __init__(self, previousE164: _Optional[int] = ...) -> None: ...

class SessionSwitchoverChatUpdate(_message.Message):
    __slots__ = ("e164",)
    E164_FIELD_NUMBER: _ClassVar[int]
    e164: int
    def __init__(self, e164: _Optional[int] = ...) -> None: ...

class GroupChangeChatUpdate(_message.Message):
    __slots__ = ("updates",)
    class Update(_message.Message):
        __slots__ = ("genericGroupUpdate", "groupCreationUpdate", "groupNameUpdate", "groupAvatarUpdate", "groupDescriptionUpdate", "groupMembershipAccessLevelChangeUpdate", "groupAttributesAccessLevelChangeUpdate", "groupAnnouncementOnlyChangeUpdate", "groupAdminStatusUpdate", "groupMemberLeftUpdate", "groupMemberRemovedUpdate", "selfInvitedToGroupUpdate", "selfInvitedOtherUserToGroupUpdate", "groupUnknownInviteeUpdate", "groupInvitationAcceptedUpdate", "groupInvitationDeclinedUpdate", "groupMemberJoinedUpdate", "groupMemberAddedUpdate", "groupSelfInvitationRevokedUpdate", "groupInvitationRevokedUpdate", "groupJoinRequestUpdate", "groupJoinRequestApprovalUpdate", "groupJoinRequestCanceledUpdate", "groupInviteLinkResetUpdate", "groupInviteLinkEnabledUpdate", "groupInviteLinkAdminApprovalUpdate", "groupInviteLinkDisabledUpdate", "groupMemberJoinedByLinkUpdate", "groupV2MigrationUpdate", "groupV2MigrationSelfInvitedUpdate", "groupV2MigrationInvitedMembersUpdate", "groupV2MigrationDroppedMembersUpdate", "groupSequenceOfRequestsAndCancelsUpdate", "groupExpirationTimerUpdate")
        GENERICGROUPUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPCREATIONUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPNAMEUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPAVATARUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPDESCRIPTIONUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPMEMBERSHIPACCESSLEVELCHANGEUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPATTRIBUTESACCESSLEVELCHANGEUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPANNOUNCEMENTONLYCHANGEUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPADMINSTATUSUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPMEMBERLEFTUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPMEMBERREMOVEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        SELFINVITEDTOGROUPUPDATE_FIELD_NUMBER: _ClassVar[int]
        SELFINVITEDOTHERUSERTOGROUPUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPUNKNOWNINVITEEUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPINVITATIONACCEPTEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPINVITATIONDECLINEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPMEMBERJOINEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPMEMBERADDEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPSELFINVITATIONREVOKEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPINVITATIONREVOKEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPJOINREQUESTUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPJOINREQUESTAPPROVALUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPJOINREQUESTCANCELEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPINVITELINKRESETUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPINVITELINKENABLEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPINVITELINKADMINAPPROVALUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPINVITELINKDISABLEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPMEMBERJOINEDBYLINKUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPV2MIGRATIONUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPV2MIGRATIONSELFINVITEDUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPV2MIGRATIONINVITEDMEMBERSUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPV2MIGRATIONDROPPEDMEMBERSUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPSEQUENCEOFREQUESTSANDCANCELSUPDATE_FIELD_NUMBER: _ClassVar[int]
        GROUPEXPIRATIONTIMERUPDATE_FIELD_NUMBER: _ClassVar[int]
        genericGroupUpdate: GenericGroupUpdate
        groupCreationUpdate: GroupCreationUpdate
        groupNameUpdate: GroupNameUpdate
        groupAvatarUpdate: GroupAvatarUpdate
        groupDescriptionUpdate: GroupDescriptionUpdate
        groupMembershipAccessLevelChangeUpdate: GroupMembershipAccessLevelChangeUpdate
        groupAttributesAccessLevelChangeUpdate: GroupAttributesAccessLevelChangeUpdate
        groupAnnouncementOnlyChangeUpdate: GroupAnnouncementOnlyChangeUpdate
        groupAdminStatusUpdate: GroupAdminStatusUpdate
        groupMemberLeftUpdate: GroupMemberLeftUpdate
        groupMemberRemovedUpdate: GroupMemberRemovedUpdate
        selfInvitedToGroupUpdate: SelfInvitedToGroupUpdate
        selfInvitedOtherUserToGroupUpdate: SelfInvitedOtherUserToGroupUpdate
        groupUnknownInviteeUpdate: GroupUnknownInviteeUpdate
        groupInvitationAcceptedUpdate: GroupInvitationAcceptedUpdate
        groupInvitationDeclinedUpdate: GroupInvitationDeclinedUpdate
        groupMemberJoinedUpdate: GroupMemberJoinedUpdate
        groupMemberAddedUpdate: GroupMemberAddedUpdate
        groupSelfInvitationRevokedUpdate: GroupSelfInvitationRevokedUpdate
        groupInvitationRevokedUpdate: GroupInvitationRevokedUpdate
        groupJoinRequestUpdate: GroupJoinRequestUpdate
        groupJoinRequestApprovalUpdate: GroupJoinRequestApprovalUpdate
        groupJoinRequestCanceledUpdate: GroupJoinRequestCanceledUpdate
        groupInviteLinkResetUpdate: GroupInviteLinkResetUpdate
        groupInviteLinkEnabledUpdate: GroupInviteLinkEnabledUpdate
        groupInviteLinkAdminApprovalUpdate: GroupInviteLinkAdminApprovalUpdate
        groupInviteLinkDisabledUpdate: GroupInviteLinkDisabledUpdate
        groupMemberJoinedByLinkUpdate: GroupMemberJoinedByLinkUpdate
        groupV2MigrationUpdate: GroupV2MigrationUpdate
        groupV2MigrationSelfInvitedUpdate: GroupV2MigrationSelfInvitedUpdate
        groupV2MigrationInvitedMembersUpdate: GroupV2MigrationInvitedMembersUpdate
        groupV2MigrationDroppedMembersUpdate: GroupV2MigrationDroppedMembersUpdate
        groupSequenceOfRequestsAndCancelsUpdate: GroupSequenceOfRequestsAndCancelsUpdate
        groupExpirationTimerUpdate: GroupExpirationTimerUpdate
        def __init__(self, genericGroupUpdate: _Optional[_Union[GenericGroupUpdate, _Mapping]] = ..., groupCreationUpdate: _Optional[_Union[GroupCreationUpdate, _Mapping]] = ..., groupNameUpdate: _Optional[_Union[GroupNameUpdate, _Mapping]] = ..., groupAvatarUpdate: _Optional[_Union[GroupAvatarUpdate, _Mapping]] = ..., groupDescriptionUpdate: _Optional[_Union[GroupDescriptionUpdate, _Mapping]] = ..., groupMembershipAccessLevelChangeUpdate: _Optional[_Union[GroupMembershipAccessLevelChangeUpdate, _Mapping]] = ..., groupAttributesAccessLevelChangeUpdate: _Optional[_Union[GroupAttributesAccessLevelChangeUpdate, _Mapping]] = ..., groupAnnouncementOnlyChangeUpdate: _Optional[_Union[GroupAnnouncementOnlyChangeUpdate, _Mapping]] = ..., groupAdminStatusUpdate: _Optional[_Union[GroupAdminStatusUpdate, _Mapping]] = ..., groupMemberLeftUpdate: _Optional[_Union[GroupMemberLeftUpdate, _Mapping]] = ..., groupMemberRemovedUpdate: _Optional[_Union[GroupMemberRemovedUpdate, _Mapping]] = ..., selfInvitedToGroupUpdate: _Optional[_Union[SelfInvitedToGroupUpdate, _Mapping]] = ..., selfInvitedOtherUserToGroupUpdate: _Optional[_Union[SelfInvitedOtherUserToGroupUpdate, _Mapping]] = ..., groupUnknownInviteeUpdate: _Optional[_Union[GroupUnknownInviteeUpdate, _Mapping]] = ..., groupInvitationAcceptedUpdate: _Optional[_Union[GroupInvitationAcceptedUpdate, _Mapping]] = ..., groupInvitationDeclinedUpdate: _Optional[_Union[GroupInvitationDeclinedUpdate, _Mapping]] = ..., groupMemberJoinedUpdate: _Optional[_Union[GroupMemberJoinedUpdate, _Mapping]] = ..., groupMemberAddedUpdate: _Optional[_Union[GroupMemberAddedUpdate, _Mapping]] = ..., groupSelfInvitationRevokedUpdate: _Optional[_Union[GroupSelfInvitationRevokedUpdate, _Mapping]] = ..., groupInvitationRevokedUpdate: _Optional[_Union[GroupInvitationRevokedUpdate, _Mapping]] = ..., groupJoinRequestUpdate: _Optional[_Union[GroupJoinRequestUpdate, _Mapping]] = ..., groupJoinRequestApprovalUpdate: _Optional[_Union[GroupJoinRequestApprovalUpdate, _Mapping]] = ..., groupJoinRequestCanceledUpdate: _Optional[_Union[GroupJoinRequestCanceledUpdate, _Mapping]] = ..., groupInviteLinkResetUpdate: _Optional[_Union[GroupInviteLinkResetUpdate, _Mapping]] = ..., groupInviteLinkEnabledUpdate: _Optional[_Union[GroupInviteLinkEnabledUpdate, _Mapping]] = ..., groupInviteLinkAdminApprovalUpdate: _Optional[_Union[GroupInviteLinkAdminApprovalUpdate, _Mapping]] = ..., groupInviteLinkDisabledUpdate: _Optional[_Union[GroupInviteLinkDisabledUpdate, _Mapping]] = ..., groupMemberJoinedByLinkUpdate: _Optional[_Union[GroupMemberJoinedByLinkUpdate, _Mapping]] = ..., groupV2MigrationUpdate: _Optional[_Union[GroupV2MigrationUpdate, _Mapping]] = ..., groupV2MigrationSelfInvitedUpdate: _Optional[_Union[GroupV2MigrationSelfInvitedUpdate, _Mapping]] = ..., groupV2MigrationInvitedMembersUpdate: _Optional[_Union[GroupV2MigrationInvitedMembersUpdate, _Mapping]] = ..., groupV2MigrationDroppedMembersUpdate: _Optional[_Union[GroupV2MigrationDroppedMembersUpdate, _Mapping]] = ..., groupSequenceOfRequestsAndCancelsUpdate: _Optional[_Union[GroupSequenceOfRequestsAndCancelsUpdate, _Mapping]] = ..., groupExpirationTimerUpdate: _Optional[_Union[GroupExpirationTimerUpdate, _Mapping]] = ...) -> None: ...
    UPDATES_FIELD_NUMBER: _ClassVar[int]
    updates: _containers.RepeatedCompositeFieldContainer[GroupChangeChatUpdate.Update]
    def __init__(self, updates: _Optional[_Iterable[_Union[GroupChangeChatUpdate.Update, _Mapping]]] = ...) -> None: ...

class GenericGroupUpdate(_message.Message):
    __slots__ = ("updaterAci",)
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    def __init__(self, updaterAci: _Optional[bytes] = ...) -> None: ...

class GroupCreationUpdate(_message.Message):
    __slots__ = ("updaterAci",)
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    def __init__(self, updaterAci: _Optional[bytes] = ...) -> None: ...

class GroupNameUpdate(_message.Message):
    __slots__ = ("updaterAci", "newGroupName")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    NEWGROUPNAME_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    newGroupName: str
    def __init__(self, updaterAci: _Optional[bytes] = ..., newGroupName: _Optional[str] = ...) -> None: ...

class GroupAvatarUpdate(_message.Message):
    __slots__ = ("updaterAci", "wasRemoved")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    WASREMOVED_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    wasRemoved: bool
    def __init__(self, updaterAci: _Optional[bytes] = ..., wasRemoved: bool = ...) -> None: ...

class GroupDescriptionUpdate(_message.Message):
    __slots__ = ("updaterAci", "newDescription")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    NEWDESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    newDescription: str
    def __init__(self, updaterAci: _Optional[bytes] = ..., newDescription: _Optional[str] = ...) -> None: ...

class GroupMembershipAccessLevelChangeUpdate(_message.Message):
    __slots__ = ("updaterAci", "accessLevel")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    ACCESSLEVEL_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    accessLevel: GroupV2AccessLevel
    def __init__(self, updaterAci: _Optional[bytes] = ..., accessLevel: _Optional[_Union[GroupV2AccessLevel, str]] = ...) -> None: ...

class GroupAttributesAccessLevelChangeUpdate(_message.Message):
    __slots__ = ("updaterAci", "accessLevel")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    ACCESSLEVEL_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    accessLevel: GroupV2AccessLevel
    def __init__(self, updaterAci: _Optional[bytes] = ..., accessLevel: _Optional[_Union[GroupV2AccessLevel, str]] = ...) -> None: ...

class GroupAnnouncementOnlyChangeUpdate(_message.Message):
    __slots__ = ("updaterAci", "isAnnouncementOnly")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    ISANNOUNCEMENTONLY_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    isAnnouncementOnly: bool
    def __init__(self, updaterAci: _Optional[bytes] = ..., isAnnouncementOnly: bool = ...) -> None: ...

class GroupAdminStatusUpdate(_message.Message):
    __slots__ = ("updaterAci", "memberAci", "wasAdminStatusGranted")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    MEMBERACI_FIELD_NUMBER: _ClassVar[int]
    WASADMINSTATUSGRANTED_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    memberAci: bytes
    wasAdminStatusGranted: bool
    def __init__(self, updaterAci: _Optional[bytes] = ..., memberAci: _Optional[bytes] = ..., wasAdminStatusGranted: bool = ...) -> None: ...

class GroupMemberLeftUpdate(_message.Message):
    __slots__ = ("aci",)
    ACI_FIELD_NUMBER: _ClassVar[int]
    aci: bytes
    def __init__(self, aci: _Optional[bytes] = ...) -> None: ...

class GroupMemberRemovedUpdate(_message.Message):
    __slots__ = ("removerAci", "removedAci")
    REMOVERACI_FIELD_NUMBER: _ClassVar[int]
    REMOVEDACI_FIELD_NUMBER: _ClassVar[int]
    removerAci: bytes
    removedAci: bytes
    def __init__(self, removerAci: _Optional[bytes] = ..., removedAci: _Optional[bytes] = ...) -> None: ...

class SelfInvitedToGroupUpdate(_message.Message):
    __slots__ = ("inviterAci",)
    INVITERACI_FIELD_NUMBER: _ClassVar[int]
    inviterAci: bytes
    def __init__(self, inviterAci: _Optional[bytes] = ...) -> None: ...

class SelfInvitedOtherUserToGroupUpdate(_message.Message):
    __slots__ = ("inviteeServiceId",)
    INVITEESERVICEID_FIELD_NUMBER: _ClassVar[int]
    inviteeServiceId: bytes
    def __init__(self, inviteeServiceId: _Optional[bytes] = ...) -> None: ...

class GroupUnknownInviteeUpdate(_message.Message):
    __slots__ = ("inviterAci", "inviteeCount")
    INVITERACI_FIELD_NUMBER: _ClassVar[int]
    INVITEECOUNT_FIELD_NUMBER: _ClassVar[int]
    inviterAci: bytes
    inviteeCount: int
    def __init__(self, inviterAci: _Optional[bytes] = ..., inviteeCount: _Optional[int] = ...) -> None: ...

class GroupInvitationAcceptedUpdate(_message.Message):
    __slots__ = ("inviterAci", "newMemberAci")
    INVITERACI_FIELD_NUMBER: _ClassVar[int]
    NEWMEMBERACI_FIELD_NUMBER: _ClassVar[int]
    inviterAci: bytes
    newMemberAci: bytes
    def __init__(self, inviterAci: _Optional[bytes] = ..., newMemberAci: _Optional[bytes] = ...) -> None: ...

class GroupInvitationDeclinedUpdate(_message.Message):
    __slots__ = ("inviterAci", "inviteeAci")
    INVITERACI_FIELD_NUMBER: _ClassVar[int]
    INVITEEACI_FIELD_NUMBER: _ClassVar[int]
    inviterAci: bytes
    inviteeAci: bytes
    def __init__(self, inviterAci: _Optional[bytes] = ..., inviteeAci: _Optional[bytes] = ...) -> None: ...

class GroupMemberJoinedUpdate(_message.Message):
    __slots__ = ("newMemberAci",)
    NEWMEMBERACI_FIELD_NUMBER: _ClassVar[int]
    newMemberAci: bytes
    def __init__(self, newMemberAci: _Optional[bytes] = ...) -> None: ...

class GroupMemberAddedUpdate(_message.Message):
    __slots__ = ("updaterAci", "newMemberAci", "hadOpenInvitation", "inviterAci")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    NEWMEMBERACI_FIELD_NUMBER: _ClassVar[int]
    HADOPENINVITATION_FIELD_NUMBER: _ClassVar[int]
    INVITERACI_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    newMemberAci: bytes
    hadOpenInvitation: bool
    inviterAci: bytes
    def __init__(self, updaterAci: _Optional[bytes] = ..., newMemberAci: _Optional[bytes] = ..., hadOpenInvitation: bool = ..., inviterAci: _Optional[bytes] = ...) -> None: ...

class GroupSelfInvitationRevokedUpdate(_message.Message):
    __slots__ = ("revokerAci",)
    REVOKERACI_FIELD_NUMBER: _ClassVar[int]
    revokerAci: bytes
    def __init__(self, revokerAci: _Optional[bytes] = ...) -> None: ...

class GroupInvitationRevokedUpdate(_message.Message):
    __slots__ = ("updaterAci", "invitees")
    class Invitee(_message.Message):
        __slots__ = ("inviterAci", "inviteeAci", "inviteePni")
        INVITERACI_FIELD_NUMBER: _ClassVar[int]
        INVITEEACI_FIELD_NUMBER: _ClassVar[int]
        INVITEEPNI_FIELD_NUMBER: _ClassVar[int]
        inviterAci: bytes
        inviteeAci: bytes
        inviteePni: bytes
        def __init__(self, inviterAci: _Optional[bytes] = ..., inviteeAci: _Optional[bytes] = ..., inviteePni: _Optional[bytes] = ...) -> None: ...
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    INVITEES_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    invitees: _containers.RepeatedCompositeFieldContainer[GroupInvitationRevokedUpdate.Invitee]
    def __init__(self, updaterAci: _Optional[bytes] = ..., invitees: _Optional[_Iterable[_Union[GroupInvitationRevokedUpdate.Invitee, _Mapping]]] = ...) -> None: ...

class GroupJoinRequestUpdate(_message.Message):
    __slots__ = ("requestorAci",)
    REQUESTORACI_FIELD_NUMBER: _ClassVar[int]
    requestorAci: bytes
    def __init__(self, requestorAci: _Optional[bytes] = ...) -> None: ...

class GroupJoinRequestApprovalUpdate(_message.Message):
    __slots__ = ("requestorAci", "updaterAci", "wasApproved")
    REQUESTORACI_FIELD_NUMBER: _ClassVar[int]
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    WASAPPROVED_FIELD_NUMBER: _ClassVar[int]
    requestorAci: bytes
    updaterAci: bytes
    wasApproved: bool
    def __init__(self, requestorAci: _Optional[bytes] = ..., updaterAci: _Optional[bytes] = ..., wasApproved: bool = ...) -> None: ...

class GroupJoinRequestCanceledUpdate(_message.Message):
    __slots__ = ("requestorAci",)
    REQUESTORACI_FIELD_NUMBER: _ClassVar[int]
    requestorAci: bytes
    def __init__(self, requestorAci: _Optional[bytes] = ...) -> None: ...

class GroupSequenceOfRequestsAndCancelsUpdate(_message.Message):
    __slots__ = ("requestorAci", "count")
    REQUESTORACI_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    requestorAci: bytes
    count: int
    def __init__(self, requestorAci: _Optional[bytes] = ..., count: _Optional[int] = ...) -> None: ...

class GroupInviteLinkResetUpdate(_message.Message):
    __slots__ = ("updaterAci",)
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    def __init__(self, updaterAci: _Optional[bytes] = ...) -> None: ...

class GroupInviteLinkEnabledUpdate(_message.Message):
    __slots__ = ("updaterAci", "linkRequiresAdminApproval")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    LINKREQUIRESADMINAPPROVAL_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    linkRequiresAdminApproval: bool
    def __init__(self, updaterAci: _Optional[bytes] = ..., linkRequiresAdminApproval: bool = ...) -> None: ...

class GroupInviteLinkAdminApprovalUpdate(_message.Message):
    __slots__ = ("updaterAci", "linkRequiresAdminApproval")
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    LINKREQUIRESADMINAPPROVAL_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    linkRequiresAdminApproval: bool
    def __init__(self, updaterAci: _Optional[bytes] = ..., linkRequiresAdminApproval: bool = ...) -> None: ...

class GroupInviteLinkDisabledUpdate(_message.Message):
    __slots__ = ("updaterAci",)
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    updaterAci: bytes
    def __init__(self, updaterAci: _Optional[bytes] = ...) -> None: ...

class GroupMemberJoinedByLinkUpdate(_message.Message):
    __slots__ = ("newMemberAci",)
    NEWMEMBERACI_FIELD_NUMBER: _ClassVar[int]
    newMemberAci: bytes
    def __init__(self, newMemberAci: _Optional[bytes] = ...) -> None: ...

class GroupV2MigrationUpdate(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GroupV2MigrationSelfInvitedUpdate(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GroupV2MigrationInvitedMembersUpdate(_message.Message):
    __slots__ = ("invitedMembersCount",)
    INVITEDMEMBERSCOUNT_FIELD_NUMBER: _ClassVar[int]
    invitedMembersCount: int
    def __init__(self, invitedMembersCount: _Optional[int] = ...) -> None: ...

class GroupV2MigrationDroppedMembersUpdate(_message.Message):
    __slots__ = ("droppedMembersCount",)
    DROPPEDMEMBERSCOUNT_FIELD_NUMBER: _ClassVar[int]
    droppedMembersCount: int
    def __init__(self, droppedMembersCount: _Optional[int] = ...) -> None: ...

class GroupExpirationTimerUpdate(_message.Message):
    __slots__ = ("expiresInMs", "updaterAci")
    EXPIRESINMS_FIELD_NUMBER: _ClassVar[int]
    UPDATERACI_FIELD_NUMBER: _ClassVar[int]
    expiresInMs: int
    updaterAci: bytes
    def __init__(self, expiresInMs: _Optional[int] = ..., updaterAci: _Optional[bytes] = ...) -> None: ...

class StickerPack(_message.Message):
    __slots__ = ("packId", "packKey")
    PACKID_FIELD_NUMBER: _ClassVar[int]
    PACKKEY_FIELD_NUMBER: _ClassVar[int]
    packId: bytes
    packKey: bytes
    def __init__(self, packId: _Optional[bytes] = ..., packKey: _Optional[bytes] = ...) -> None: ...

class ChatStyle(_message.Message):
    __slots__ = ("wallpaperPreset", "wallpaperPhoto", "autoBubbleColor", "bubbleColorPreset", "customColorId", "dimWallpaperInDarkMode")
    class WallpaperPreset(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_WALLPAPER_PRESET: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_BLUSH: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_COPPER: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_DUST: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_CELADON: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_RAINFOREST: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_PACIFIC: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_FROST: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_NAVY: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_LILAC: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_PINK: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_EGGPLANT: _ClassVar[ChatStyle.WallpaperPreset]
        SOLID_SILVER: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_SUNSET: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_NOIR: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_HEATMAP: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_AQUA: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_IRIDESCENT: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_MONSTERA: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_BLISS: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_SKY: _ClassVar[ChatStyle.WallpaperPreset]
        GRADIENT_PEACH: _ClassVar[ChatStyle.WallpaperPreset]
    UNKNOWN_WALLPAPER_PRESET: ChatStyle.WallpaperPreset
    SOLID_BLUSH: ChatStyle.WallpaperPreset
    SOLID_COPPER: ChatStyle.WallpaperPreset
    SOLID_DUST: ChatStyle.WallpaperPreset
    SOLID_CELADON: ChatStyle.WallpaperPreset
    SOLID_RAINFOREST: ChatStyle.WallpaperPreset
    SOLID_PACIFIC: ChatStyle.WallpaperPreset
    SOLID_FROST: ChatStyle.WallpaperPreset
    SOLID_NAVY: ChatStyle.WallpaperPreset
    SOLID_LILAC: ChatStyle.WallpaperPreset
    SOLID_PINK: ChatStyle.WallpaperPreset
    SOLID_EGGPLANT: ChatStyle.WallpaperPreset
    SOLID_SILVER: ChatStyle.WallpaperPreset
    GRADIENT_SUNSET: ChatStyle.WallpaperPreset
    GRADIENT_NOIR: ChatStyle.WallpaperPreset
    GRADIENT_HEATMAP: ChatStyle.WallpaperPreset
    GRADIENT_AQUA: ChatStyle.WallpaperPreset
    GRADIENT_IRIDESCENT: ChatStyle.WallpaperPreset
    GRADIENT_MONSTERA: ChatStyle.WallpaperPreset
    GRADIENT_BLISS: ChatStyle.WallpaperPreset
    GRADIENT_SKY: ChatStyle.WallpaperPreset
    GRADIENT_PEACH: ChatStyle.WallpaperPreset
    class BubbleColorPreset(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_BUBBLE_COLOR_PRESET: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_ULTRAMARINE: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_CRIMSON: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_VERMILION: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_BURLAP: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_FOREST: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_WINTERGREEN: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_TEAL: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_BLUE: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_INDIGO: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_VIOLET: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_PLUM: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_TAUPE: _ClassVar[ChatStyle.BubbleColorPreset]
        SOLID_STEEL: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_EMBER: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_MIDNIGHT: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_INFRARED: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_LAGOON: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_FLUORESCENT: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_BASIL: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_SUBLIME: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_SEA: _ClassVar[ChatStyle.BubbleColorPreset]
        GRADIENT_TANGERINE: _ClassVar[ChatStyle.BubbleColorPreset]
    UNKNOWN_BUBBLE_COLOR_PRESET: ChatStyle.BubbleColorPreset
    SOLID_ULTRAMARINE: ChatStyle.BubbleColorPreset
    SOLID_CRIMSON: ChatStyle.BubbleColorPreset
    SOLID_VERMILION: ChatStyle.BubbleColorPreset
    SOLID_BURLAP: ChatStyle.BubbleColorPreset
    SOLID_FOREST: ChatStyle.BubbleColorPreset
    SOLID_WINTERGREEN: ChatStyle.BubbleColorPreset
    SOLID_TEAL: ChatStyle.BubbleColorPreset
    SOLID_BLUE: ChatStyle.BubbleColorPreset
    SOLID_INDIGO: ChatStyle.BubbleColorPreset
    SOLID_VIOLET: ChatStyle.BubbleColorPreset
    SOLID_PLUM: ChatStyle.BubbleColorPreset
    SOLID_TAUPE: ChatStyle.BubbleColorPreset
    SOLID_STEEL: ChatStyle.BubbleColorPreset
    GRADIENT_EMBER: ChatStyle.BubbleColorPreset
    GRADIENT_MIDNIGHT: ChatStyle.BubbleColorPreset
    GRADIENT_INFRARED: ChatStyle.BubbleColorPreset
    GRADIENT_LAGOON: ChatStyle.BubbleColorPreset
    GRADIENT_FLUORESCENT: ChatStyle.BubbleColorPreset
    GRADIENT_BASIL: ChatStyle.BubbleColorPreset
    GRADIENT_SUBLIME: ChatStyle.BubbleColorPreset
    GRADIENT_SEA: ChatStyle.BubbleColorPreset
    GRADIENT_TANGERINE: ChatStyle.BubbleColorPreset
    class Gradient(_message.Message):
        __slots__ = ("angle", "colors", "positions")
        ANGLE_FIELD_NUMBER: _ClassVar[int]
        COLORS_FIELD_NUMBER: _ClassVar[int]
        POSITIONS_FIELD_NUMBER: _ClassVar[int]
        angle: int
        colors: _containers.RepeatedScalarFieldContainer[int]
        positions: _containers.RepeatedScalarFieldContainer[float]
        def __init__(self, angle: _Optional[int] = ..., colors: _Optional[_Iterable[int]] = ..., positions: _Optional[_Iterable[float]] = ...) -> None: ...
    class CustomChatColor(_message.Message):
        __slots__ = ("id", "solid", "gradient")
        ID_FIELD_NUMBER: _ClassVar[int]
        SOLID_FIELD_NUMBER: _ClassVar[int]
        GRADIENT_FIELD_NUMBER: _ClassVar[int]
        id: int
        solid: int
        gradient: ChatStyle.Gradient
        def __init__(self, id: _Optional[int] = ..., solid: _Optional[int] = ..., gradient: _Optional[_Union[ChatStyle.Gradient, _Mapping]] = ...) -> None: ...
    class AutomaticBubbleColor(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    WALLPAPERPRESET_FIELD_NUMBER: _ClassVar[int]
    WALLPAPERPHOTO_FIELD_NUMBER: _ClassVar[int]
    AUTOBUBBLECOLOR_FIELD_NUMBER: _ClassVar[int]
    BUBBLECOLORPRESET_FIELD_NUMBER: _ClassVar[int]
    CUSTOMCOLORID_FIELD_NUMBER: _ClassVar[int]
    DIMWALLPAPERINDARKMODE_FIELD_NUMBER: _ClassVar[int]
    wallpaperPreset: ChatStyle.WallpaperPreset
    wallpaperPhoto: FilePointer
    autoBubbleColor: ChatStyle.AutomaticBubbleColor
    bubbleColorPreset: ChatStyle.BubbleColorPreset
    customColorId: int
    dimWallpaperInDarkMode: bool
    def __init__(self, wallpaperPreset: _Optional[_Union[ChatStyle.WallpaperPreset, str]] = ..., wallpaperPhoto: _Optional[_Union[FilePointer, _Mapping]] = ..., autoBubbleColor: _Optional[_Union[ChatStyle.AutomaticBubbleColor, _Mapping]] = ..., bubbleColorPreset: _Optional[_Union[ChatStyle.BubbleColorPreset, str]] = ..., customColorId: _Optional[int] = ..., dimWallpaperInDarkMode: bool = ...) -> None: ...
