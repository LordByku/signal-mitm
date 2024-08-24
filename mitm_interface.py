from signal_protocol import identity_key, storage, protocol, session_cipher, session, kem
from signal_protocol.state import SessionRecord
from signal_protocol.kem import SerializedCiphertext, KeyPair as KyberKeyPair, KeyType

from signal_protocol.address import ProtocolAddress, DeviceId
from signal_protocol.state import PreKeyId, KyberPreKeyId, SignedPreKeyId, SignedPreKeyRecord, PreKeyBundle, PreKeyRecord

from signal_protocol.curve import KeyPair, PrivateKey, PublicKey
from signal_protocol.identity_key import IdentityKey, IdentityKeyPair
from signal_protocol.ratchet import (
    BobSignalProtocolParameters,
    initialize_bob_session,
    AliceSignalProtocolParameters,
    initialize_alice_session,
)

import json
import base64

import logging

from test_protocol_wip import Protocol

FORMAT = '%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s'
logging.basicConfig(format=FORMAT)
logging.getLogger().setLevel(logging.INFO)


class MitmUser(object):
    def __init__(self, *args, **kwargs):

        ############ FAKE USER ############
        self.address = kwargs.get("address", ProtocolAddress("1", 1))

        self.identity_key_pair = kwargs.get("identity_key",identity_key.IdentityKeyPair.generate())
        self.registration_id = kwargs.get("RID", 1)

        self.store = storage.InMemSignalProtocolStore(self.identity_key_pair, self.registration_id)

        self.pre_key_pair = KeyPair.generate()
        self.signed_pre_key_pair = KeyPair.generate()

        self.signed_pre_key_public = self.signed_pre_key_pair.public_key().serialize()

        self.signed_pre_key_signature = (
            self.store.get_identity_key_pair()
            .private_key()
            .calculate_signature(self.signed_pre_key_public)
        )

        self.pre_key_id = PreKeyId(31337)
        self.signed_pre_key_id = SignedPreKeyId(22)

        self.pre_key_bundle = PreKeyBundle(
            self.store.get_local_registration_id(),
            DeviceId(1),
            (self.pre_key_id, self.pre_key_pair.public_key()),
            self.signed_pre_key_id,
            self.signed_pre_key_pair.public_key(),
            self.signed_pre_key_signature,
            self.store.get_identity_key_pair().identity_key(),
        )

        self.kyber_pre_key_id = KyberPreKeyId(24)
        self.kyber_pre_key_pair :kem.KeyPair = kem.KeyPair.generate(kem.KeyType(0))
        self.kyber_pre_key_signature = self.identity_key_pair.private_key().calculate_signature(
                                            self.kyber_pre_key_pair.get_public().serialize()
                                        )


        self.pre_key_bundle = self.pre_key_bundle.with_kyber_pre_key(
            self.kyber_pre_key_id,
            self.kyber_pre_key_pair.get_public(),
            self.kyber_pre_key_signature
        )

        self.last_resort_kyber: kem.KeyPair = kem.KeyPair.generate(kem.KeyType(0))
        # self.prekey = None

    def __getstate__(self):
        state = self.__dict__.copy()
        state['address'] = (self.address.name(), self.address.device_id())
        state['identity_key_pair'] = self.identity_key_pair.to_base64()
        state['pre_key_pair'] = self.pre_key_pair.public_key().to_base64(), self.pre_key_pair.private_key().to_base64()
        # del self.store

        state['signed_pre_key_pair'] = self.signed_pre_key_pair.public_key().to_base64(), self.signed_pre_key_pair.private_key().to_base64()
        del self.signed_pre_key_public
        state['signed_pre_key_signature'] = base64.b64encode(self.signed_pre_key_signature).decode()
        state['pre_key_id'] = self.signed_pre_key_id.get_id()
        state['signed_pre_key_id'] = self.signed_pre_key_id.get_id()
        state['kyber_pre_key_id'] = self.kyber_pre_key_id.get_id()
        state['kyber_pre_key_signature'] = base64.b64encode(self.kyber_pre_key_signature).decode()
        state['last_resort_kyber'] = self.last_resort_kyber.to_base64()
        state['kyber_pre_key_pair'] = self.kyber_pre_key_pair.to_base64()
        del state['pre_key_bundle']
        del state['store']
        return state

    def __setstate__(self, state):
        self.address = ProtocolAddress(state['address'][0], state['address'][1])
        self.identity_key_pair = IdentityKeyPair.from_base64(state['identity_key_pair'].encode())
        self.pre_key_pair = KeyPair.from_public_and_private(
            base64.b64decode(state['pre_key_pair'][0]),
            base64.b64decode(state['pre_key_pair'][1])
        )
        self.signed_pre_key_pair = KeyPair.from_public_and_private(
            base64.b64decode(state['signed_pre_key_pair'][0]),
            base64.b64decode(state['signed_pre_key_pair'][1])
        )
        self.signed_pre_key_signature = base64.b64decode(state['signed_pre_key_signature'])
        self.pre_key_id = PreKeyId(state['pre_key_id'])
        self.signed_pre_key_id = SignedPreKeyId(state['signed_pre_key_id'])
        self.kyber_pre_key_id = KyberPreKeyId(state['kyber_pre_key_id'])
        self.kyber_pre_key_signature = base64.b64decode(state['kyber_pre_key_signature'])
        self.last_resort_kyber = kem.KeyPair.from_base64(state['last_resort_kyber'][0].encode(), state['last_resort_kyber'][1].encode())
        self.kyber_pre_key_pair = kem.KeyPair.from_base64(state['kyber_pre_key_pair'][0].encode(), state['kyber_pre_key_pair'][1].encode())


    def set_pre_key_bundle(self, pre_key_bundle: PreKeyBundle):
        self.pre_key_bundle = pre_key_bundle

    def check_session(self, address: ProtocolAddress):
        return self.store.load_session(address)

    def is_session_kyber_enabled(self, peer_address: ProtocolAddress):
        return self.store.load_session(peer_address).session_version() == 4

    # TODO : Check if this makes sense here or in the MitmVictim class
    def process_pre_key_bundle(self, address: ProtocolAddress, pre_key_bundle: PreKeyBundle):
        session.process_prekey_bundle(address, self.store, pre_key_bundle)

        # return self.store.load_session(address) and self.store.load_session(address).session_version() == 3

    def encrypt(self, address: ProtocolAddress, plaintext: bytes):
        return session_cipher.message_encrypt(self.store, address, plaintext)

    def decrypt(self, address: ProtocolAddress, ciphertext):

        try:
            ciphertext = protocol.PreKeySignalMessage.try_from(ciphertext)
        except Exception:
            pass

        try:
            ciphertext = protocol.SignalMessage.try_from(ciphertext)
        except Exception:
            pass

        self.prekey = PreKeyRecord(self.pre_key_id, self.pre_key_pair)
        self.store.save_pre_key(self.pre_key_id, self.prekey)

        signed_prekey = SignedPreKeyRecord(
            self.signed_pre_key_id,
            42,
            self.signed_pre_key_pair,
            self.signed_pre_key_signature,
        )

        self.store.save_signed_pre_key(self.signed_pre_key_id, signed_prekey)

        return session_cipher.message_decrypt(self.store, address, ciphertext)


if __name__ == "__main__":
    PRE_KYBER_MESSAGE_VERSION = 3
    KYBER_AWARE_MESSAGE_VERSION = 4
    KYBER_1024_KEY_TYPE = KeyType(0)

    # fetch the prekeybundle extract and put it in a prekeybundle object

    with open('docs/bundle.json') as f:
        example_bundle = json.load(f)

    bob_identity_key_public = base64.b64decode(example_bundle["identityKey"])
    bob_signed_pre_key_public = base64.b64decode(example_bundle["devices"][0]["signedPreKey"]["publicKey"])
    bob_pre_key_public = base64.b64decode(example_bundle["devices"][0]["preKey"]["publicKey"])

    print(base64.b64decode(example_bundle["devices"][0]["signedPreKey"]["signature"] + "==").hex())

    bob_bundle = PreKeyBundle(
        1,
        DeviceId(1),
        (PreKeyId(example_bundle["devices"][0]["preKey"]["keyId"]), PublicKey.deserialize(bob_pre_key_public)),
        SignedPreKeyId(1),
        PublicKey.deserialize(bob_signed_pre_key_public),
        base64.b64decode(example_bundle["devices"][0]["signedPreKey"]["signature"] + "=="),
        identity_key.IdentityKey(bob_identity_key_public),
    )
    bob_addr = ProtocolAddress("1", 1)

    bob_kyber_pre_key_public = base64.b64decode(example_bundle["devices"][0]["pqPreKey"]["publicKey"])
    bob_kyber_pre_key_signature = base64.b64decode(example_bundle["devices"][0]["pqPreKey"]["signature"] + "==")
    bob_kyber_pre_key_id = example_bundle["devices"][0]["pqPreKey"]["keyId"]

    bob_bundle = bob_bundle.with_kyber_pre_key(KyberPreKeyId(bob_kyber_pre_key_id),
                                               kem.PublicKey.deserialize(bob_kyber_pre_key_public),
                                               bob_kyber_pre_key_signature)

    print((bob_bundle.signed_pre_key_public().serialize().hex(), bob_bundle.signed_pre_key_signature().hex()))

    print(bob_bundle.has_kyber_pre_key())

    alice = MitmUser()

    alice.process_pre_key_bundle(bob_addr, bob_bundle)

    original_message = b"Hobgoblins hold themselves to high standards of military honor"

    enc = alice.encrypt(bob_addr, original_message)
    assert enc.message_type() == 3  # PreKey Signal message https://github.com/signalapp/libsignal/blob/f2ae8436b365f5e4e1371102f4702f51ac34e02c/rust/protocol/src/protocol.rs#L33C1-L38
    assert alice.is_session_kyber_enabled(bob_addr), "not a kyber session :( "

    print(f"Encrypted message: {enc.serialize().hex()}")

# protocol.PreKeySignalMessage()
