from signal_protocol import (
    curve,
    address,
    identity_key,
    state,
    storage,
    protocol,
    session_cipher,
    session,
    kem,
)
import os

import logging
from protos.gen import *
from protos.gen.SignalService_pb2 import *
from protos.gen.wire_pb2 import *
from protos.gen.storage_pb2 import *
import datetime as dt
import time

bold_red = "\x1b[31;1m"
reset = "\x1b[0m"

logging.getLogger().setLevel(logging.INFO)


def current_milli_time():
    return round(time.time() * 1000)


def notifu(msg: str) -> None:
    print(f"{bold_red}{msg}{reset}")
    # msg = "Your message here"
    os.system(f'/usr/bin/notify-send "Time Now" "{msg}"')


class MitmUser(object):
    def __init__(self, *args, **kwargs):

        ############ FAKE USER ############
        self.address = kwargs.get("address", address.ProtocolAddress("1", 1))

        self.identity_key_pair = identity_key.IdentityKeyPair.generate()
        self.registration_id = kwargs.get("RID", 1)

        self.store = storage.InMemSignalProtocolStore(
            self.identity_key_pair, self.registration_id
        )

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

        # self.kyber_pre_key_id = state.KyberPreKeyId(13915770)
        # self.kyber_pre_key_pair = kem.KeyPair.generate(kem.KeyType(0))

        self.kyber_record = state.KyberPreKeyRecord.generate(kem.KeyType(0), state.KyberPreKeyId(13915770),
                                                             self.identity_key_pair.private_key())
        # print(kyber_pre_key_pair.get_public().serialize().hex())

        self.kyber_pre_key_signature = (
            self.identity_key_pair.private_key().calculate_signature(
                self.kyber_record.key_pair().get_public().serialize()
            )
        )

        self.pre_key_bundle = self.pre_key_bundle.with_kyber_pre_key(
            state.KyberPreKeyId(13915770),
            self.kyber_record.key_pair().get_public(),
            self.kyber_pre_key_signature,
        )

        self.store.save_kyber_pre_key(state.KyberPreKeyId(13915770), self.kyber_record)
        #todo a : not expsoed in the annotations 

        ############ LEGIT USER ############
        # These info are retrieved from the intercept event hooks

    # def __str__(self):
    #    return f"MitmUser: {self.address, self.identity_key_pair.serialize(), self.registration_id, self.store, self.pre_key_pair.serialize(), self.signed_pre_key_pair.serialize(), self.signed_pre_key_signature, self.pre_key_id, self.signed_pre_key_id, self.pre_key_bundle, self.kyber_pre_key_id, self.kyber_pre_key_pair.serialize(), self.kyber_pre_key_signature, self.pre_key_bundle}"

    def check_session(self, address: address.ProtocolAddress):
        return self.store.load_session(address)

    # TODO : Check if this makes sense here or in the MitmVictim class
    def process_pre_key_bundle(
            self, address: address.ProtocolAddress, pre_key_bundle: state.PreKeyBundle
    ):
        session.process_prekey_bundle(address, self.store, pre_key_bundle)
        # return self.store.load_session(address) and self.store.load_session(address).session_version() == 3

    def save_bundle(self, address: address.ProtocolAddress):
        return self.store.store_pre_key_bundle(address, self.pre_key_bundle)

    def encrypt(self, address: address.ProtocolAddress, plaintext: bytes):
        return session_cipher.message_encrypt(self.store, address, plaintext)

    def decrypt(self, address: address.ProtocolAddress, ciphertext: protocol.CiphertextMessage):

        ciphertext = ciphertext.serialize()

        try:
            ciphertext = protocol.PreKeySignalMessage.try_from(ciphertext)
        except Exception as e:
            pass

        try:
            ciphertext = protocol.SignalMessage.try_from(ciphertext)
        except Exception as e:
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


# Create MitmUser instances
Alice = MitmUser(address=address.ProtocolAddress("alice", 1), RID=1)
Bob = MitmUser(address=address.ProtocolAddress("bob", 1), RID=2)
#print(Alice.pre_key_bundle.kyber_pre_key_id())

assert Alice.store.load_session(Bob.address) is None

print(f"Bob's pre_key_bundle: {Bob.pre_key_bundle.to_dict()}")

Alice.process_pre_key_bundle(Bob.address, Bob.pre_key_bundle)

print(f"Session version {Alice.store.load_session(Bob.address).session_version()}")
assert Alice.store.load_session(Bob.address).session_version() == 4

original_message = b"Hobgoblins hold themselves to high standards of military honor"

#enc = Alice.encrypt(Bob.address, original_message).serialize()

#BuildSignalMessage

# DataMessage
# Content
# SignalMessage
# PreKeySignalMessage

data_message = DataMessage()
data_message.body = b"Hello, World!"
###### Stuff that you can get from the original message (and save the profile_key) or generate it your self 
data_message.profileKey = b"adrianoooo"
data_message.timestamp = current_milli_time()

content = Content()
content.dataMessage.CopyFrom(data_message)
serializedContent = (content.SerializeToString())

#print(f"serializedContent: {serializedContent}")

cipher = Alice.encrypt(Bob.address, serializedContent)
cipher_2 = Alice.encrypt(Bob.address, serializedContent)

print(f"cipher: {cipher.serialize().hex()}")
print(f"cipher_2: {cipher_2.serialize().hex()}")

Bob.store.save_identity(
    Alice.address, Alice.store.get_identity_key_pair().identity_key()
)

dec = Bob.decrypt(Alice.address, cipher)

#print(f"Bob decrypts {dec}")

bobs_response = b"Who watches the watchers?"

assert Bob.check_session(Alice.address)

bobs_session_with_alice = Bob.check_session(Alice.address)
assert bobs_session_with_alice.session_version() == 4
assert len(bobs_session_with_alice.alice_base_key()) == 32 + 1

bob_outgoing = Bob.encrypt(Alice.address, bobs_response)
assert bob_outgoing.message_type() == 2  # 2 == CiphertextMessageType::Whisper

# Now back to fake alice

alice_decrypts = Alice.decrypt(Bob.address, bob_outgoing)
notifu(f"Alice decrypts '{alice_decrypts.decode()}'")
assert alice_decrypts == bobs_response
