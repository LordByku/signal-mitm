# Requirements:
# apt install python3 python3-pip
# pip3 install cryptography==2.8 pycrypto

import base64
from dataclasses import dataclass
import logging
from typing import Optional
import hmac, hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding

from binascii import unhexlify, hexlify
from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
from proto_python import *
from time import time

from Crypto.Cipher import AES

DISC_BYTES =  b"\xFF"*32
MAC_LENGTH = 8


def hex2PubKey(hexStr) -> X25519PublicKey:
    key = X25519PublicKey.from_public_bytes(unhexlify(hexStr[2:]))
    sanity = hexlify(key.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw)).decode()

    if hexStr[2:].lower() != sanity:
        print("we got a missmatch :( ")
    return key

def hex2PrivKey(hexStr) -> X25519PrivateKey:
    key = X25519PrivateKey.from_private_bytes(unhexlify(hexStr))
    sanity = hexlify(key.private_bytes(encoding=Encoding.Raw,format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())).decode()

    if hexStr.lower() != sanity:
        print("we got a missmatch :( ")
    return key

def PubKey2Hex(pubKey: X25519PublicKey) -> str:
    if pubKey is None:
        return ""
    hexStr = "05" + pubKey.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw).hex()

    return hexStr

def PrivKey2Hex(privKey: X25519PrivateKey) -> str:
    hexStr = privKey.private_bytes(encoding=Encoding.Raw,format=PrivateFormat.Raw, encryption_algorithm= NoEncryption()).hex()
    
    return hexStr

def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)


def unpad(msg):
    # remove pkcs7 padding
    return msg[: -msg[-1]]

def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode("utf-8").strip()

def hmac_sha256(key: bytes, msg: bytes):
    result = hmac.new(key, msg, digestmod=hashlib.sha256).hexdigest()
    return result

def hkdf(inp, length, salt=None, info=None):
    # use HKDF on an input to derive a key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        #backend=default_backend(),
    )
    return hkdf.derive(inp)

def aes_256_cbc_encrypt(ptxt, key, iv):
    #padder = padding.PKCS7(256).padder()

    #ptxt = padder.update(ptxt) + padder.finalize()
    
    ptxt = pad(ptxt)
    #print(ptxt, len(ptxt))

    return AES.new((key), AES.MODE_CBC, iv).encrypt(ptxt)


def get_padded_message_length(message_length):
    message_length_with_terminator = message_length + 1
    message_part_count = message_length_with_terminator // 160

    if message_length_with_terminator % 160 != 0:
        message_part_count += 1

    return message_part_count * 160

def get_padded_message_body(message_body):

    padded_length = get_padded_message_length(len(message_body) + 1) - 1
    padded_message = bytearray(padded_length)
    padded_message[:len(message_body)] = message_body
    padded_message[len(message_body)] = 0x80

    return bytes(padded_message) ## PCKS7

def get_stripped_padding_message_body(message_with_padding):
    padding_start = 0

    for i in range(len(message_with_padding) - 1, 0, -1):
        if message_with_padding[i] == 0x80:
            padding_start = i
            break
        elif message_with_padding[i] != 0x00:
            print(message_with_padding)
            print("Padding byte is malformed, returning unstripped padding.")
            return message_with_padding

    stripped_message = message_with_padding[:padding_start]

    return stripped_message

def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)


def unpad(msg):
    # remove pkcs7 padding
    return msg[: -msg[-1]]

def derive_keys(sk):
    return sk[:32], sk[32:64]

def verify_mac(msg:bytes, mac_key: bytes, sender_IK: X25519PublicKey, receiver_IK: X25519PublicKey):
    
    our_mac = compute_mac(msg[:len(msg)-MAC_LENGTH], mac_key, sender_IK, receiver_IK)
    their_mac = msg[len(msg) - MAC_LENGTH : ]
    
    
    result = our_mac == their_mac
    if not result:
        # A warning instead of an error because we try multiple sessions.
        logging.warning(
            "Bad Mac! Their Mac: {} Our Mac: {}".format(
                their_mac.hex(),
                our_mac.hex()
            )
        )
    return result
    
def compute_mac(msg:bytes, mac_key: bytes, sender_IK: X25519PublicKey, receiver_IK: X25519PublicKey) -> bytes:
    if len(mac_key) != 32:
        raise ValueError("InvalidMacKeyLength: {}".format(len(mac_key)))

    mac = hmac.new(key=mac_key,msg=None,digestmod=hashlib.sha256)
    mac.update(bytes.fromhex(PubKey2Hex(sender_IK)))
    mac.update(bytes.fromhex(PubKey2Hex(receiver_IK)))
    mac.update(msg)
    return mac.digest()[:8]

class PreKeySignalMessageClass(object):
    def __init__(self, pre_key_id = 0, base_key = None, identity_key = None, message = None, registration_id  = 0, signed_pre_key_id = 0):
        self.pksm = PreKeySignalMessage()
        self.pksm.pre_key_id = pre_key_id
        self.pksm.base_key = base_key
        self.pksm.identity_key = identity_key
        self.pksm.message = message # SignalMessage
        self.pksm.registration_id = registration_id
        self.pksm.signed_pre_key_id = signed_pre_key_id
    
    def getPrekeyID(self):
        return self.pre_key_id
    def getBaseKey(self):
        return self.base_key
    def getRegistrationID(self):
        return self.registration_id
    def getIdentityKey(self):
        return self.identity_key
    def getMessage(self):
        return self.message
    def getSignedPrekeyID(self):
        return self.signed_pre_key
    def SerializeToString(self):
        return self.pksm.SerializeToString()
    def ParseFromString(self):
        return self.pksm.ParseFromString()


class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b""):
        # turn the ratchet, changing the state and yielding a new key and IV
        msg_kdf = hmac_sha256((self.state), b'\x01')
        msg_key = hkdf(bytes.fromhex(msg_kdf), 80, None, b"WhisperMessageKeys")
        
        cipher_key = msg_key[0:32]
        mac_key =  msg_key[32:64]
        iv = msg_key[64:]

        self.state = bytes.fromhex(hmac_sha256(self.state, b'\x02'))
        
        return cipher_key, mac_key, iv

@dataclass
class KeyBundle:
    IK: X25519PublicKey
    SPK: Optional[X25519PublicKey] = None
    OPK: Optional[X25519PublicKey] = None
    EK: Optional[X25519PublicKey] = None
    
def user2AliceBundle(usr):
    # utility method so you don't pass a whole user to x3dh
    pkeys = {
        'IK': usr.IK.public_key(),
        'SPK': usr.SPK.public_key() if hasattr(usr, 'SPK') else None,
        'OPK': usr.OPK.public_key() if hasattr(usr, 'OPK') else None,
        'EK': usr.EK.public_key() if hasattr(usr, 'EK') else None
    }
    return KeyBundle(**pkeys)

def user2BobBundle(usr):
    pkeys = {
        'IK': usr.IK,
        'SPK': usr.SPK if hasattr(usr, 'SPK') else None,
        'OPK': usr.OPK if hasattr(usr, 'OPK') else None,
        'EK': usr.EK if hasattr(usr, 'EK') else None
    }
    return KeyBundle(**pkeys)

def user2Bundle(usr):
    # utility method so you don't pass a whole user to x3dh
    pkeys = {
        'IK': usr.IK.public_key(),
        'SPK': usr.SPK.public_key() if hasattr(usr, 'SPK') else None,
        'OPK': usr.OPK.public_key() if hasattr(usr, 'OPK') else None,
        'EK': usr.EK.public_key() if hasattr(usr, 'EK') else None
    }
    return KeyBundle(**pkeys)


class Human(object):
    
    new_DH_key = False
    last_DH_key = None
    
    def enc(self, msg: bytes) -> bytes:
        key, mac_key, iv = self.send_ratchet.next()
        paddedContent = get_padded_message_body(msg)
        cipher = aes_256_cbc_encrypt(paddedContent, key, iv)
        return cipher, mac_key

    def dec(self, ctxt: bytes, pubkey: bytes) -> bytes:
        # receive the new public key and use it to perform a DH
        key, _, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = get_stripped_padding_message_body(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ctxt)))
        return msg

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(self.sk[:32])
        self.chainValue = SymmRatchet(self.sk[32:])
        # initialise the sending and recving chains
        self.send_ratchet = SymmRatchet(self.chainValue)
        self.recv_ratchet = SymmRatchet(self.chainValue)
    
    def x3dh(self, other_bundle: KeyBundle):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        if other_bundle.SPK is not None: 
            dh1 = self.IK.exchange(other_bundle.SPK)
            dh2 = self.EK.exchange(other_bundle.IK)
            dh3 = self.EK.exchange(other_bundle.SPK)
            dh4 = self.EK.exchange(other_bundle.OPK)
            self.sk = hkdf(inp = DISC_BYTES + dh1 + dh2 + dh3 + dh4, length=64, info = b"WhisperText")
            self.init_ratchets()
            self.dh_ratchet(other_bundle.SPK)
        #TODO change this
        else:
            dh1 = self.SPK.exchange(other_bundle.IK)
            dh2 = self.IK.exchange(other_bundle.EK)
            dh3 = self.SPK.exchange(other_bundle.EK)
            dh4 = self.OPK.exchange(other_bundle.EK)
            self.sk = hkdf(inp = DISC_BYTES + dh1 + dh2 + dh3 + dh4, length=64, info = b"WhisperText")
            self.init_ratchets()
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        print(f"[{self.__class__.__name__}]\tShared key:", (bytes.hex(self.sk)))


    def recv(self, cipher, bob_public_key):
        if PubKey2Hex(bob_public_key) != PubKey2Hex(self.last_DH_key):
            self.new_DH_key = True
            self.last_DH_key = bob_public_key
            self.dh_ratchet(bob_public_key)
        msg = self.dec(cipher, bob_public_key)
        print(f"[{self.__class__.__name__}]\tDecrypted message:", msg)
        self.last_person = False #####
        
    def send(self, other, msg):
        cipher, _ = self.enc(msg)
        print(f"[{self.__class__.__name__}]\tSending ciphertext to {other.__class__.__name__}:", b64(cipher))
        # send ciphertext and current DH public key
        other.recv(cipher, self.DHratchet.public_key())
        self.last_person = True #####

    def dh_ratchet(self, other_pub_DH):
        # perform a DH ratchet rotation using Bob's public key
        if self.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = self.DHratchet.exchange(other_pub_DH)
            sk = hkdf(dh_recv, 64, self.root_ratchet.state, b"WhisperRatchet")
            recv_chain_root_key, recv_chain_chain_key = derive_keys(sk)
            print(f"recvSK {sk.hex()}")
            self.root_ratchet.state = recv_chain_root_key
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.recv_ratchet = SymmRatchet(recv_chain_chain_key)
            #print(f"[{self.__class__.__name__}]\tRecv ratchet seed:", b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.DHratchet = X25519PrivateKey.generate()
        ## TODO do a stronger check on casual key repeating
        #self.DHratchet= hex2PrivKey("187d54327d675dfc283b28d34fffbb09158cda316df079cd2d84f5928a94de7e")
        dh_send = self.DHratchet.exchange(other_pub_DH)
        sk = hkdf(dh_send, 64, self.root_ratchet.state, b"WhisperRatchet")
        sender_chain_root_key, sending_chain_chain_key = derive_keys(sk)
        print(f"sendSK {sk.hex()}")

        self.root_ratchet.state = sender_chain_root_key
        print(sender_chain_root_key.hex(), sending_chain_chain_key.hex())
        #shared_send = self.root_ratchet.next(dh_send)[0]
        
        self.send_ratchet = SymmRatchet(sending_chain_chain_key)
        #print(f"[{self.__class__.__name__}]\tSend ratchet seed:", b64(shared_send))


class Alice(Human):
    def __init__(self, *args, **kwargs):
        # generate Alice's keys
        self.IK = kwargs.get("IK", X25519PrivateKey.generate())
        self.EK = kwargs.get("EK", X25519PrivateKey.generate())
        # Alice's DH ratchet starts out uninitialised
        self.DHratchet = None

class Bob(Human):
    def __init__(self, *args, **kwargs):
        # generate Bob's keys
        self.IK = kwargs.get("privIK", X25519PrivateKey.generate())
        #self.IK = kwargs.get("IK", X25519PrivateKey.generate().public_key())
        
        self.SPK = kwargs.get("privSPK", X25519PrivateKey.generate())
        #self.SPK = kwargs.get("SPK",  X25519PrivateKey.generate().public_key())
        
        self.OPK = kwargs.get("privOPK", X25519PrivateKey.generate())
        #self.OPK = kwargs.get("OPK",  X25519PrivateKey.generate().public_key())
        
        
        #self.DHratchet = kwargs.get("DH", X25519PrivateKey.generate())
        self.DHratchet = self.SPK
        self.last_DH_key = self.DHratchet.public_key()

class Protocol:
    def __init__(self, alice: Alice, bob: Bob):
        self.alice = alice
        self.bob = bob
    
    def handshake(self):
        alice_bundle = user2Bundle(self.alice)
        bob_bundle = user2Bundle(self.bob)
        
        self.alice.x3dh(bob_bundle)
        self.bob.x3dh(alice_bundle)
        
    def AliceSendToBob (self, msg, profileKey, timestamp):
        
        data_message = DataMessage()
        data_message.body = msg
        ###### Stuff that you can get from the original message (and save the profile_key) or generate it your self 
        data_message.profileKey = profileKey
        data_message.timestamp = timestamp
        ######
        content = Content()
        content.dataMessage.CopyFrom(data_message)
    
        serializedContent = (content.SerializeToString())

        cipher, mac_key = self.alice.enc(serializedContent)
        print(f"[{self.alice.__class__.__name__}]\tSending ciphertext to {bob.__class__.__name__}:", b64(cipher))

        self.bob.recv(cipher, self.alice.DHratchet.public_key())
        self.last_person = True
                
        signalMessage = SignalMessage()
        signalMessage.ratchet_key = bytes.fromhex(PubKey2Hex(self.alice.DHratchet.public_key()))
        signalMessage.counter = 1
        signalMessage.previous_counter = 0
        signalMessage.ciphertext = msg
             
        sm = bytes.fromhex("33") + signalMessage.SerializeToString()
    
        mac = compute_mac(sm, mac_key, self.alice.IK.public_key(), self.bob.IK.public_key() )
        sm = sm + mac   
    
        '''       
        preKeySignalMessage = PreKeySignalMessage()
        preKeySignalMessage.pre_key_id = 4917741
        preKeySignalMessage.base_key = self.alice.EK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        preKeySignalMessage.identity_key = self.alice.IK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        preKeySignalMessage.message = sm # SignalMessage
        preKeySignalMessage.registration_id = 6027
        preKeySignalMessage.signed_pre_key_id = 13819045'''

        preKeySignalMessage = PreKeySignalMessageClass(4917741,
                                                  self.alice.EK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  self.alice.IK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  sm,
                                                  6027,
                                                  13819045)

        pksm = bytes.fromhex("33") + preKeySignalMessage.SerializeToString()
        
        wire_msg = base64.b64encode(pksm)
        
        return wire_msg

if __name__ == "__main__":
    alice, bob = Alice(), Bob()
    alice_bundle,bob_bundle = user2Bundle(alice), user2Bundle(bob)

    # Alice performs an X3DH while Bob is offline, using his uploaded keys
    alice.x3dh(bob_bundle)

    # Bob comes online and performs an X3DH using Alice's public keys (IK, EK)
    bob.x3dh(alice_bundle)
    
    assert(alice.sk==bob.sk)

    # Initialize their symmetric ratchets
    #alice.init_ratchets()
    #bob.init_ratchets()

    # Print out the matching pairs (debug)
    '''   
    print("[Alice]\tsend ratchet:", list(map(b64, alice.send_ratchet.next())))
    print("[Bob]\trecv ratchet:", list(map(b64, bob.recv_ratchet.next())))
    print("[Alice]\trecv ratchet:", list(map(b64, alice.recv_ratchet.next())))
    print("[Bob]\tsend ratchet:", list(map(b64, bob.send_ratchet.next())))
    '''
    # Initialise Alice's sending ratchet with Bob's public key
    #alice.dh_ratchet(bob.DHratchet.public_key())

    # Alice sends Bob a message and her new DH ratchet public key
    alice.send(bob, b"Hello Bob!")

    # Bob uses that information to sync with Alice and send her a message
    bob.send(alice, b"Hello to you too, Alice!")

    alice.send(bob, b"Do you like Pizza?")

    ## From this point forward the code fucks up.
    ## TODO @andrea - figure it out
    ## Figure it out with multiple messages from one party

    #alice.dh_ratchet(bob.DHratchet.public_key())
    bob.send(alice, b"Hic sunt leones")
    alice.send(bob, b"Let's do crime")
    print(alice.last_person)
    bob.send(alice, b"Si!")
    #bob.dh_ratchet(alice.DHratchet.public_key())

    bob.send(alice, b"HELL YEAH!!!")
    print(alice.last_person)
    print(bob.last_person)
    
    alice.send(bob, b"Cosa succede?")
    prot = Protocol(alice, bob)
    
    print(prot.AliceSendToBob(b"heyyyyy", b'casual', int(time())))
