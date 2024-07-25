from signal_protocol import curve, address, identity_key, state, storage, protocol, session_cipher, session, kem
from signal_protocol.state import SessionRecord
from signal_protocol.kem import SerializedCiphertext, KeyPair as KyberKeyPair, KeyType

# from signal_protocol.protocol import KemSerializedCiphertext
from signal_protocol.curve import KeyPair, PrivateKey, PublicKey
from signal_protocol.identity_key import IdentityKey, IdentityKeyPair
from signal_protocol.ratchet import (
    BobSignalProtocolParameters,
    initialize_bob_session,
    AliceSignalProtocolParameters,
    initialize_alice_session,
)

import json, base64

class MitmUser(object):
    def __init__(self, *args, **kwargs):
        
        ############ FAKE USER ############
        self.address = kwargs.get("address", address.ProtocolAddress("1", 1))
        
        self.identity_key_pair = identity_key.IdentityKeyPair.generate()
        self.registration_id = kwargs.get("RID", 1)

        self.store = storage.InMemSignalProtocolStore(self.identity_key_pair, self.registration_id)

        self.pre_key_pair = curve.KeyPair.generate()
        self.signed_pre_key_pair = curve.KeyPair.generate()

        self.signed_pre_key_public = self.signed_pre_key_pair.public_key().serialize()


        self.signed_pre_key_signature = (
            self.store.get_identity_key_pair()
            .private_key()
            .calculate_signature(self.signed_pre_key_public)
        )

        self.pre_key_id = state.PreKeyId(31337)
        self.signed_pre_key_id = state.SignedPreKeyId(22)

        self.pre_key_bundle = state.PreKeyBundle(
            self.store.get_local_registration_id(),
            address.DeviceId(1),
            (self.pre_key_id, self.pre_key_pair.public_key()),
            self.signed_pre_key_id,
            self.signed_pre_key_pair.public_key(),
            self.signed_pre_key_signature,
            self.store.get_identity_key_pair().identity_key(),
        )

    def check_session(self, address:address.ProtocolAddress):
        return self.store.load_session(address)
    
    #TODO : Check if this makes sense here or in the MitmVictim class
    def process_pre_key_bundle(self, address:address.ProtocolAddress, pre_key_bundle:state.PreKeyBundle):
        session.process_prekey_bundle(address, self.store, pre_key_bundle)
        #return self.store.load_session(address) and self.store.load_session(address).session_version() == 3
    
    def save_bundle(self, address:address.ProtocolAddress):
        return self.store.store_pre_key_bundle(address, self.pre_key_bundle)

    def encrypt(self, address:address.ProtocolAddress, plaintext:bytes):
        return session_cipher.message_encrypt(self.store, address, plaintext)

    def decrypt(self, address:address.ProtocolAddress, ciphertext):
        
        try:
            ciphertext = protocol.PreKeySignalMessage.try_from(ciphertext)
        except Exception:
            pass

        try:
            ciphertext = protocol.SignalMessage.try_from(ciphertext)
        except Exception:
            pass

        self.prekey = state.PreKeyRecord(self.pre_key_id, self.pre_key_pair)
        self.store.save_pre_key(self.pre_key_id, self.prekey)

        signed_prekey = state.SignedPreKeyRecord(
            self.signed_pre_key_id,
            42,
            self.signed_pre_key_pair,
            self.signed_pre_key_signature,
        )

        self.store.save_signed_pre_key(self.signed_pre_key_id, signed_prekey)

        return session_cipher.message_decrypt(self.store, address, ciphertext)

PRE_KYBER_MESSAGE_VERSION = 3
KYBER_AWARE_MESSAGE_VERSION = 4
KYBER_1024_KEY_TYPE = KeyType(0)

#fetch the prekeybundle extract and put it in a prekeybundle object

with open('docs/bundle.json') as f:
    example_bundle = json.load(f)

bob_identity_key_public = base64.b64decode(example_bundle["identityKey"])
bob_signed_pre_key_public = base64.b64decode(example_bundle["devices"][0]["signedPreKey"]["publicKey"])
bob_pre_key_public = base64.b64decode(example_bundle["devices"][0]["preKey"]["publicKey"])

print(base64.b64decode(example_bundle["devices"][0]["signedPreKey"]["signature"] + "==").hex())

bob_bundle = state.PreKeyBundle(
        1,
        address.DeviceId(1),
        (state.PreKeyId(example_bundle["devices"][0]["preKey"]["keyId"]), PublicKey.deserialize(bob_pre_key_public)),
        state.SignedPreKeyId(1),
        PublicKey.deserialize(bob_signed_pre_key_public),
        base64.b64decode(example_bundle["devices"][0]["signedPreKey"]["signature"] + "=="),
        identity_key.IdentityKey(bob_identity_key_public),
)

bob_kyber_pre_key_public = base64.b64decode(example_bundle["devices"][0]["pqPreKey"]["publicKey"])
bob_kyber_pre_key_signature = base64.b64decode(example_bundle["devices"][0]["pqPreKey"]["signature"] + "==")
bob_kyber_pre_key_id = example_bundle["devices"][0]["pqPreKey"]["keyId"]

bob_bundle = bob_bundle.with_kyber_pre_key(state.KyberPreKeyId(bob_kyber_pre_key_id), kem.PublicKey.deserialize(bob_kyber_pre_key_public), bob_kyber_pre_key_signature)

print((bob_bundle.signed_pre_key_public().serialize().hex(), bob_bundle.signed_pre_key_signature().hex()))

print(bob_bundle.has_kyber_pre_key())

alice = MitmUser()

alice.process_pre_key_bundle(address.ProtocolAddress("1", 1), bob_bundle)

original_message = b"Hobgoblins hold themselves to high standards of military honor"


print(alice.encrypt(address.ProtocolAddress("1", 1), original_message).message_type())

alice_identity_key_pair = IdentityKeyPair.generate()
alice_base_key_pair = KeyPair.generate()

bob_ephemeral_key_pair = KeyPair.generate()
bob_identity_key_pair = IdentityKeyPair.generate()
bob_signed_pre_key_pair = KeyPair.generate()

bob_kyber_pre_key_pair = KyberKeyPair.generate(KYBER_1024_KEY_TYPE)


# protocol.PreKeySignalMessage()


