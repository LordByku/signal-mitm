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
import json

from implementation import *

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

        self.pre_key_id = state.PreKeyId(14566991)
        self.signed_pre_key_id = state.SignedPreKeyId(13472625)

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

        self.kyber_record = state.KyberPreKeyRecord.generate(kem.KeyType(0), state.KyberPreKeyId(13915770), self.identity_key_pair.private_key())
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

        # self.store.save_kyber_pre_key(state.KyberPreKeyId(13915770), self.kyber_record)
        self.store.save_kyber_pre_key(self.kyber_record.id(), self.kyber_record)
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

class Mitm:
    def __init__(self, victim: MitmUser, user:MitmUser):
        self.fake_victim = victim
        self.fake_user = user

        self.messages_exchange = []

    def receive_message_from_victim(self, address: address.ProtocolAddress, ciphertext: protocol.CiphertextMessage):
        ptxt = self.fake_user.decrypt(address, ciphertext)
        self.messages_exchange.append([address, self.fake_victim.address, ptxt, time.ctime()])
        return ptxt

    def receive_message_from_user(self, address: address.ProtocolAddress, ciphertext: protocol.CiphertextMessage):
        ptxt = self.fake_victim.decrypt(address, ciphertext)
        self.messages_exchange.append([address, self.fake_user.address, ptxt, time.ctime()])
        return ptxt
    
    def send_message_to_victim(self, address: address.ProtocolAddress, plaintext: bytes):
        ciphertext = self.fake_user.encrypt(address, plaintext)
        self.messages_exchange.append([self.fake_user.address, address, plaintext, time.ctime()])
        return ciphertext

    def send_message_to_user(self, address: address.ProtocolAddress, plaintext: bytes):
        ciphertext = self.fake_victim.encrypt(address, plaintext)
        self.messages_exchange.append([self.fake_victim.address, address, plaintext, time.ctime()])
        return ciphertext
    
    def receive_pre_key_bundle(self, address: address.ProtocolAddress, pre_key_bundle: state.PreKeyBundle):
        self.fake_victim.process_pre_key_bundle(address, pre_key_bundle)

    def intercept_and_modifying(self, address: address.ProtocolAddress, ciphertext: protocol.CiphertextMessage):
        if address.name() == self.fake_victim.address.name():
            text = self.receive_message_from_victim(address, ciphertext)
            print(f"Mitm received message from victim {text}")
            flag = input("Do you want to send this message to the user? (y/n) ")
            if flag == "y":
                return self.send_message_to_user(self.fake_user.address, text)
            if flag == "n":
                message = bytes(input("Enter the message you want to send to the user: "), 'utf-8')
                return self.send_message_to_user(self.fake_user.address, message)

        elif address.name() == self.fake_user.address.name():
            text = self.receive_message_from_user(address, ciphertext)
            print(f"Mitm received message from user {text}")
            flag = input("Do you want to send this message to the victim? (y/n) ")
            if flag == "y":
                return self.send_message_to_victim(self.fake_victim.address, text)
            if flag == "n":
                message = bytes(input("Enter the message you want to send to the user: "), 'utf-8')
                return self.send_message_to_victim(self.fake_victim.address, message)

def test_alice_to_bob():
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
    #print(f"cipher_2: {cipher_2.serialize().hex()}")


    print(cipher.serialize() == cipher_2.serialize())

    # Bob.store.save_identity(
    #     Alice.address, Alice.store.get_identity_key_pair().identity_key()
    # )

    dec = Bob.decrypt(Alice.address, cipher)

    print(f"Bob decrypts {dec}")

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

    print(Alice.encrypt(Bob.address, serializedContent).serialize().hex())

def test_mitm_alice_to_bob():

    ####### ENDPOINT /v2/keys/

    Real_Alice = MitmUser(address=address.ProtocolAddress("alice", 1), RID=1)
    Real_Bob = MitmUser(address=address.ProtocolAddress("bob", 1), RID=2)

    Fake_Bob = MitmUser(address=address.ProtocolAddress("bob", 1), RID=2)
    Fake_Alice = MitmUser(address=address.ProtocolAddress("alice", 1), RID=1)
    mitm = Mitm(Fake_Alice, Fake_Bob)

    # Fake Alice process the pre key bundle of Bob
    mitm.receive_pre_key_bundle(Real_Bob.address, Real_Bob.pre_key_bundle)


    Real_Alice.process_pre_key_bundle(Fake_Bob.address, Fake_Bob.pre_key_bundle)

    ###### ENDPOINT /v2/keys/ 

    ####### ENDPOINT /v1/messages/ inside websocket

    # Alice sends a message to Bob (Fake_Bob)
    original_message = b"Hello, Bob!"
    enc = Real_Alice.encrypt(Fake_Bob.address, original_message)

    # Mitm intercepts the pre key bundle
    message = mitm.intercept_and_modifying(Real_Alice.address, enc)

    print(message.serialize().hex())

    clear_text = Real_Bob.decrypt(Fake_Alice.address, message)

    print(clear_text)

    # Mitm intercepts the message
    bob_alice_message = Real_Bob.encrypt(Fake_Alice.address, clear_text + b" fuck this")

    print(bob_alice_message.serialize().hex())

    dec_message = mitm.intercept_and_modifying(Real_Bob.address, bob_alice_message)

    print(Real_Alice.decrypt(Fake_Bob.address, dec_message))

    # # Mitm sends his own pre key bundle to Bob
    # Mitm.process_pre_key_bundle(Bob.address, Mitm.pre_key_bundle)

    # # Bob receives Mitm's pre key bundle
    # Bob.process_pre_key_bundle(Mitm.address, Mitm.pre_key_bundle)

    # # Bob receives Alice's pre key bundle
    # Bob.process_pre_key_bundle(Alice.address, Alice.pre_key_bundle)

    # # Alice sends a message to Bob
    # original_message = b"Hello, Bob!"
    # enc = Alice.encrypt(Bob.address, original_message)

    # # Mitm intercepts the message
    # dec = Mitm.decrypt(Bob.address, enc)

    # notifu(f"Mitm intercepts '{dec.decode()}'")

    # # Bob receives the message
    # dec = Bob.decrypt(Alice.address, enc)

    # notifu(f"Bob decrypts '{dec.decode()}'")

    # assert dec == original_message

def test_mitm_bob_to_alice():
    Real_Alice = MitmUser(address=address.ProtocolAddress("alice", 1), RID=1)
    Real_Bob = MitmUser(address=address.ProtocolAddress("bob", 1), RID=2)

    Fake_Bob = MitmUser(address=address.ProtocolAddress("bob", 1), RID=2)
    Fake_Alice = MitmUser(address=address.ProtocolAddress("alice", 1), RID=1)
    mitm = Mitm(Fake_Alice, Fake_Bob)

    Fake_Bob.process_pre_key_bundle(Real_Alice.address, Real_Alice.pre_key_bundle)

    Real_Bob.process_pre_key_bundle(Fake_Alice.address, Fake_Alice.pre_key_bundle)
    bob_ctx = Real_Bob.encrypt(Fake_Alice.address, b"Hello, Alice!")

    # Alice process the pre key bundle of Bob
    msg = mitm.intercept_and_modifying(Real_Bob.address, bob_ctx)

    print(Real_Alice.decrypt(Fake_Bob.address, msg))

    print(mitm.messages_exchange)


def function():

    a = "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"
    

    req = '{  "destination":"PNI:50c9062e-17ab-44d2-9ba8-6843c5945729",  "messages":[     {       "content":"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",      "destinationDeviceId":1,      "destinationRegistrationId":13926,      "type":3      }  ],  "online":true,  "timestamp": 1721651490130,  "urgent":false}'

    req = json.loads(req)

    fakeUser = MitmUser(address=address.ProtocolAddress("bob", 1), RID=1)

    dst = req["destination"].split(":")[1]

    for msg in req["messages"]:
        if msg["destinationDeviceId"] != 1:
            logging.error(f"Secondary devices are not supported")
            continue

        envelope_type = EnvelopeType(int(msg['type']))
        logging.warning(f"MESSAGE (Envelope) TYPE: {envelope_type}")

        if envelope_type not in [EnvelopeType.PREKEY_BUNDLE]:
            logging.warning(f"Only PREKEY_BUNDLE is supported at the moment, got {envelope_type}.)")
            continue

        content = b64decode(msg["content"])

        msg_type = OutgoingMessageType(int(msg["type"]))
        if msg_type == OutgoingMessageType.PREKEY_BUNDLE:

            fakeUser.decrypt(address.ProtocolAddress(dst, msg["destinationDeviceId"]), protocol.PreKeySignalMessage.try_from(content))

        # logging.warning(f"ctxt from IK: {b64encode(ctxt.identity_key).decode()}")


function()

#test_alice_to_bob()EEEEEEE