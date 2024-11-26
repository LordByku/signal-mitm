from typing import Optional

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
from signal_protocol.storage import InMemSignalProtocolStore
from sqlmodel import select

from db.database import ConversationSession
from db.session import DatabaseSessionManager

from src.mitm_interface import MitmUser, MitmVisitenKarte, VisitenKarteType

from signal_protocol.identity_key import IdentityKey

class TestSessionOperations(unittest.TestCase):

    def test_session(self):
        DEVICE_ID = 1
        alice_address = ProtocolAddress("+14151111111", DEVICE_ID)
        bob_address = ProtocolAddress("+14151111112", DEVICE_ID)


        def alice_bob_chat_session(alice_address: ProtocolAddress, bob_address: ProtocolAddress) -> tuple[SessionRecord, SessionRecord, InMemSignalProtocolStore, InMemSignalProtocolStore]:

            alice = MitmUser(protocol_address=alice_address, aci_uuid="alice_aci", pni_uuid="alice_pni")
            bob = MitmUser(protocol_address=bob_address, aci_uuid="bob_aci", pni_uuid="bob_pni")

            bob_pre_key_bundle = bob.generate_pre_key_bundle(VisitenKarteType.ACI)

            alice_store = alice.get_aci_visitenkarte().get_store()

            assert alice.get_aci_visitenkarte().get_store().load_session(bob_address) is None

            # Below standalone function would make more sense as a method on alice_store?
            alice.process_pre_key_bundle(
                alice.get_visitenkarte(VisitenKarteType.ACI).get_karte_type(),
                bob_address,
                bob_pre_key_bundle,
            )

            assert alice_store.load_session(bob_address)
            assert alice_store.load_session(bob_address).session_version() == 3

            original_message = b"Hobgoblins hold themselves to high standards of military honor"

            outgoing_message = alice.encrypt(VisitenKarteType.ACI, bob_address, original_message)

            assert outgoing_message.message_type() == 3  # 3 == CiphertextMessageType::PreKey
            outgoing_message_wire = outgoing_message.serialize()

            # Now over to fake Bob for processing the first message

            incoming_message = outgoing_message_wire

            # bob_prekey = PreKeyRecord(bob.get_pre_key_record(VisitenKarteType.ACI).id(), bob.get_visitenkarte(VisitenKarteType.ACI).get_pre_key_record(bob.get_pre_key_record(VisitenKarteType.ACI).id()))
            # bob_store.save_pre_key(bob.get_pre_key_record(VisitenKarteType.ACI).id(), bob_prekey)
            bob_store = bob.get_visitenkarte(VisitenKarteType.ACI).get_store()

            assert bob_store.load_session(alice_address) is None

            plaintext = bob.decrypt(VisitenKarteType.ACI, alice_address, incoming_message)

            assert original_message == plaintext

            bobs_response = b"Who watches the watchers?"


            assert bob_store.load_session(alice_address)

            bobs_session_with_alice = bob_store.load_session(alice_address)
            assert bobs_session_with_alice.session_version() == 3
            assert len(bobs_session_with_alice.alice_base_key()) == 32 + 1

            bob_outgoing = message_encrypt(bob_store, alice_address, bobs_response)
            assert bob_outgoing.message_type() == 2  # 2 == CiphertextMessageType::Whisper

            # Now back to fake alice

            alice_decrypts = message_decrypt(alice_store, bob_address, bob_outgoing)
            assert alice_decrypts == bobs_response

            return alice_store.load_session(bob_address), bob_store.load_session(alice_address), alice_store, bob_store


        print("[x] Let Alice and Bob chat")
        alice_with_bob_sesh, bob_with_alice_sesh, alice_store, bob_store = alice_bob_chat_session(alice_address, bob_address)
        # alice_with_bob_sesh.to
        print(alice_with_bob_sesh.to_base64())
        print(bob_with_alice_sesh.to_base64())

        print("[x] Creating db session")
        alice_chat_sesh = ConversationSession(
            store_uuid=alice_address.name(),
            store_device_id=alice_address.device_id(),
            other_service_id=bob_address.name(),
            other_device_id=bob_address.device_id(),
            otherIdentityKey=IdentityKey(bob_with_alice_sesh.remote_identity_key_bytes()),
            session_record=alice_with_bob_sesh,
        )

        bob_chat_sesh = ConversationSession(
            store_uuid = bob_address.name(),
            store_device_id = bob_address.device_id(),
            other_service_id = alice_address.name(),
            other_device_id = alice_address.device_id(),
            otherIdentityKey = IdentityKey(alice_with_bob_sesh.remote_identity_key_bytes()),
            session_record = bob_with_alice_sesh,
        )

        print(alice_chat_sesh)
        print(bob_chat_sesh)

        # dummy_session_record =

        print("[x] Reset existing sessions :c")
        alice_store.store_session(bob_address, SessionRecord.new_fresh())
        bob_store.store_session(alice_address, SessionRecord.new_fresh())

        assert alice_store.load_session(bob_address)
        assert bob_store.load_session(alice_address)
        assert alice_store.load_session(bob_address).to_base64() == ""
        assert bob_store.load_session(alice_address).to_base64() == ""

        print("[x] Save to db")

        with DatabaseSessionManager().get_session() as session:
            session.merge(alice_chat_sesh)
            session.merge(bob_chat_sesh)
            session.commit()

            del alice_chat_sesh
            del bob_chat_sesh


        print("[x] Fetch from db")
        alice_chat_sesh, bob_chat_sesh = None, None

        with DatabaseSessionManager().get_session() as session:
            alice_chat_sesh: Optional[ConversationSession] = session.exec(
                select(ConversationSession).where(ConversationSession.store_uuid == alice_address.name())
            ).first()
            bob_chat_sesh: Optional[ConversationSession] = session.exec(
                select(ConversationSession).where(ConversationSession.store_uuid == bob_address.name())
            ).first()

        assert alice_chat_sesh is not None
        assert bob_chat_sesh is not None

        print(alice_chat_sesh)
        print(bob_chat_sesh)

        assert alice_chat_sesh.session_record.to_base64() == alice_with_bob_sesh.to_base64()
        assert bob_chat_sesh.session_record.to_base64() == bob_with_alice_sesh.to_base64()

        alice_store.store_session(bob_address, alice_chat_sesh.session_record)
        bob_store.store_session(alice_address, bob_chat_sesh.session_record)


        assert alice_store.load_session(bob_address).to_base64() == alice_with_bob_sesh.to_base64()
        assert bob_store.load_session(alice_address).to_base64() == bob_with_alice_sesh.to_base64()

if __name__ == '__main__':
    unittest.main()