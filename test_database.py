import unittest
from unittest.mock import patch
from database import VisitenKarte, User, Device, ConversationSession, StoreKeyRecord, LegitKeyRecord
from session import DatabaseSessionManager
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.state import SessionRecord
import json

class TestDatabaseOperations(unittest.TestCase):

    def setUp(self):
        # Mock database session manager
        self.session_manager = DatabaseSessionManager()
        self.session = self.session_manager.get_session()

        # Setup identity keys
        self.aci_identity_key_pair = IdentityKeyPair.generate()
        self.pni_identity_key_pair = IdentityKeyPair.generate()

        # Setup user and devices
        self.alice = User(
            aci="aci",
            pni="pni",
            phone_number="+1234567890",
            aci_identity_key=self.aci_identity_key_pair,
            pni_identity_key=self.pni_identity_key_pair,
            is_victim=True,
            unidentified_access_key="unidentified_access_key",
        )

        self.alice_primary_device = Device(
            aci="aci",
            pni="pni",
            device_id=1,
            user=self.alice,
        )

        self.alice_vk = VisitenKarte(
            type="aci",
            registration_id=1,
            uuid="alice",
            device_id="1",
            identityKey=self.aci_identity_key_pair,
        )

        self.alice_store_key_record = StoreKeyRecord(
            uuid="aci",
            deviceId=1,
            identityKey=self.aci_identity_key_pair,
            registrationId=1,
        )

        self.session_record = SessionRecord.new_fresh()

        self.alice_convo = ConversationSession(
            store_uuid="aci",
            store_device_id=1,
            other_service_id="bob",
            other_device_id=1,
            identityKey=self.aci_identity_key_pair.public_key(),
            session_record=self.session_record,
        )

        with open("debug/bundle.json") as f:
            bundle = json.load(f)
            bundle["devices"][0]["identityKey"] = bundle["identityKey"]
            bundle = bundle["devices"][0]
            bundle["uuid"] = "test1"
            bundle["type"] = "aci"
            bundle["preKey"] = [bundle["preKey"]]
            bundle["pqPreKey"] = [bundle["pqPreKey"]]

            self.lb = LegitKeyRecord.model_validate(bundle)

    def test_database_insertion_and_retrieval(self):
        with self.session as session:
            # Merge records into the session
            session.merge(self.alice)
            session.merge(self.alice_primary_device)
            session.merge(self.alice_vk)
            session.merge(self.alice_store_key_record)
            session.merge(self.alice_convo)
            session.merge(self.lb)

            # Commit the session
            session.commit()

            # Verify retrieval of identity keypair
            result = VisitenKarte.get_identity_keypair(session, "aci", "alice", 1)
            print(f"RESULT {result}")
            self.assertIsNotNone(result, "Failed to retrieve identity keypair")
            self.assertEqual(result.private_key().serialize(), self.aci_identity_key_pair.private_key().serialize(), "Retrieved identity keypair does not match")

if __name__ == '__main__':
    unittest.main()