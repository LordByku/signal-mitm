from typing import Optional

from signal_protocol.address import DeviceId, ProtocolAddress
from signal_protocol.curve import KeyPair
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.protocol import PreKeySignalMessage
from signal_protocol.session import process_prekey_bundle
from signal_protocol.session_cipher import message_decrypt, message_encrypt
from signal_protocol.state import (
    PreKeyBundle,
    PreKeyId,
    PreKeyRecord,
    SessionRecord,
    SignedPreKeyId,
    SignedPreKeyRecord,
)
from signal_protocol.storage import InMemSignalProtocolStore
from sqlmodel import select

from db.database import ConversationSession, Device, StoreKeyRecord, User, VisitenKarte, LegitKeyRecord
from db.session import DatabaseSessionManager
import json 

from src.mitm_interface import MitmUser, MitmVisitenKarte, VisitenKarteType

from signal_protocol.identity_key import IdentityKey
import unittest
from signal_protocol.address import DeviceId, ProtocolAddress
from signal_protocol.curve import KeyPair
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.protocol import PreKeySignalMessage
from signal_protocol.session import process_prekey_bundle
from signal_protocol.session_cipher import message_decrypt, message_encrypt
from signal_protocol.state import (
    PreKeyBundle,
    PreKeyId,
    PreKeyRecord,
    SessionRecord,
    SignedPreKeyId,
    SignedPreKeyRecord,
)

from db.dbhacks import PydanticSignedPreKey
from typing import get_args

class TestRegistration(unittest.TestCase):

    def registration_request_endpoint(self):
        # /v1/registration request coming
        with open("debug/bundle.json") as f:
            reg_req = json.loads(f)

            # Create a new user
            legit_records = LegitKeyRecord(
                type=VisitenKarteType.ACI,
                uuid="",
                deviceId=1,
                registrationId=reg_req["accountAttributes"]["registrationId"],
                identityKey=IdentityKey.from_base64(reg_req["aciIdentityKey"].encode()),
                signedPreKey= get_args(PydanticSignedPreKey)[1].validate_from_dict(reg_req["aciSignedPreKey"]),
                
 
            )

if __name__ == '__main__':
    unittest.main()
