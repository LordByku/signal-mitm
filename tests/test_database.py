import pytest
from unittest.mock import patch
from db.database import VisitenKarte, User, Device, ConversationSession, StoreKeyRecord, LegitKeyRecord
from db.session import DatabaseSessionManager, Session
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.state import SessionRecord
import json

@pytest.fixture
def setup_database() -> dict[Session, User, Device, VisitenKarte, StoreKeyRecord, ConversationSession, LegitKeyRecord, IdentityKeyPair]:
    # Mock database session manager
    session_manager = DatabaseSessionManager()
    session = session_manager.get_session()

    # Setup identity keys
    aci_identity_key_pair = IdentityKeyPair.generate()
    pni_identity_key_pair = IdentityKeyPair.generate()

    # Setup user and devices
    alice = User(
        aci="aci",
        pni="pni",
        phone_number="+1234567890",
        aci_identity_key=aci_identity_key_pair,
        pni_identity_key=pni_identity_key_pair,
        is_victim=True,
        unidentified_access_key="unidentified_access_key",
    )

    alice_primary_device = Device(
        aci="aci",
        pni="pni",
        device_id=1,
        user=alice,
    )

    alice_vk = VisitenKarte(
        type="aci",
        registration_id=1,
        uuid="alice",
        device_id="1",
        identityKey=aci_identity_key_pair,
    )

    alice_store_key_record = StoreKeyRecord(
        uuid="aci",
        deviceId=1,
        identityKey=aci_identity_key_pair,
        registrationId=1,
    )

    session_record = SessionRecord.new_fresh()

    alice_convo = ConversationSession(
        store_uuid="aci",
        store_device_id=1,
        other_service_id="bob",
        other_device_id=1,
        identityKey=aci_identity_key_pair.public_key(),
        session_record=session_record,
    )

    with open("tests/fixtures/bundle.json") as f:
        bundle = json.load(f)
        bundle["devices"][0]["identityKey"] = bundle["identityKey"]
        bundle = bundle["devices"][0]
        bundle["uuid"] = "test1"
        bundle["type"] = "aci"
        bundle["preKey"] = [bundle["preKey"]]
        bundle["pqPreKey"] = [bundle["pqPreKey"]]
        bundle["PqLastResortPreKey"] = None

        lb = LegitKeyRecord.model_validate(bundle)

    return {
        "session": session,
        "alice": alice,
        "alice_primary_device": alice_primary_device,
        "alice_vk": alice_vk,
        "alice_store_key_record": alice_store_key_record,
        "alice_convo": alice_convo,
        "lb": lb,
        "aci_identity_key_pair": aci_identity_key_pair,
    }

def test_database_insertion_and_retrieval(setup_database):
    session: Session = setup_database["session"]
    alice: User = setup_database["alice"]
    alice_primary_device: Device = setup_database["alice_primary_device"]
    alice_vk: VisitenKarte = setup_database["alice_vk"]
    alice_store_key_record: StoreKeyRecord = setup_database["alice_store_key_record"]
    alice_convo: ConversationSession = setup_database["alice_convo"]
    lb: LegitKeyRecord = setup_database["lb"]
    aci_identity_key_pair: IdentityKeyPair = setup_database["aci_identity_key_pair"]

    with session as s:
        # Merge records into the session
        s.merge(alice)
        s.merge(alice_primary_device)
        s.merge(alice_vk)
        s.merge(alice_store_key_record)
        s.merge(alice_convo)
        s.merge(lb)

        # Commit the session
        s.commit()

        # Verify retrieval of identity keypair
        result:IdentityKeyPair = VisitenKarte.get_identity_keypair(s, "aci", "alice", 1)
        print(f"RESULT {result}")
        assert result is not None, "Failed to retrieve identity keypair"
        assert result.private_key().serialize() == aci_identity_key_pair.private_key().serialize(), "Retrieved identity keypair does not match"