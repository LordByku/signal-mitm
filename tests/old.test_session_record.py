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

from db.database import ConversationSession
from db.session import DatabaseSessionManager

DEVICE_ID = 1
alice_address = ProtocolAddress("+14151111111", DEVICE_ID)
bob_address = ProtocolAddress("+14151111112", DEVICE_ID)


def alice_bob_chat_session() -> tuple[SessionRecord, SessionRecord, InMemSignalProtocolStore, InMemSignalProtocolStore]:
    alice_identity_key_pair = IdentityKeyPair.generate()
    bob_identity_key_pair = IdentityKeyPair.generate()

    alice_registration_id = 1  # TODO: generate these
    bob_registration_id = 2

    alice_store = InMemSignalProtocolStore(alice_identity_key_pair, alice_registration_id)
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    bob_pre_key_pair = KeyPair.generate()
    bob_signed_pre_key_pair = KeyPair.generate()

    bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key().serialize()

    bob_signed_pre_key_signature = (
        bob_store.get_identity_key_pair().private_key().calculate_signature(bob_signed_pre_key_public)
    )

    pre_key_id = PreKeyId(31337)
    signed_pre_key_id = SignedPreKeyId(22)

    bob_pre_key_bundle = PreKeyBundle(
        bob_store.get_local_registration_id(),
        DeviceId(DEVICE_ID),
        (pre_key_id, bob_pre_key_pair.public_key()),
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    assert alice_store.load_session(bob_address) is None

    # Below standalone function would make more sense as a method on alice_store?
    process_prekey_bundle(
        bob_address,
        alice_store,
        bob_pre_key_bundle,
    )

    assert alice_store.load_session(bob_address)
    assert alice_store.load_session(bob_address).session_version() == 3

    original_message = b"Hobgoblins hold themselves to high standards of military honor"

    outgoing_message = message_encrypt(alice_store, bob_address, original_message)
    assert outgoing_message.message_type() == 3  # 3 == CiphertextMessageType::PreKey
    outgoing_message_wire = outgoing_message.serialize()

    # Now over to fake Bob for processing the first message

    incoming_message = PreKeySignalMessage.try_from(outgoing_message_wire)

    bob_prekey = PreKeyRecord(pre_key_id, bob_pre_key_pair)
    bob_store.save_pre_key(pre_key_id, bob_prekey)

    signed_prekey = SignedPreKeyRecord(
        signed_pre_key_id,
        42,
        bob_signed_pre_key_pair,
        bob_signed_pre_key_signature,
    )

    bob_store.save_signed_pre_key(signed_pre_key_id, signed_prekey)

    assert bob_store.load_session(alice_address) is None

    plaintext = message_decrypt(bob_store, alice_address, incoming_message)

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
alice_with_bob_sesh, bob_with_alice_sesh, alice_store, bob_store = alice_bob_chat_session()
# alice_with_bob_sesh.to
print(alice_with_bob_sesh.to_base64())
print(bob_with_alice_sesh.to_base64())

print("[x] Creating db session")
alice_chat_sesh = ConversationSession(
    store_aci=alice_address.name(),
    store_device_id=alice_address.device_id(),
    others_service_id=bob_address.name(),
    other_device_id=bob_address.device_id(),
    session_record=alice_with_bob_sesh,
)

bob_chat_sesh = ConversationSession(
    store_aci=bob_address.name(),
    store_device_id=bob_address.device_id(),
    others_service_id=alice_address.name(),
    other_device_id=alice_address.device_id(),
    session_record=bob_with_alice_sesh,
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
        select(ConversationSession).where(ConversationSession.store_aci == alice_address.name())
    ).first()
    bob_chat_sesh: Optional[ConversationSession] = session.exec(
        select(ConversationSession).where(ConversationSession.store_aci == bob_address.name())
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
