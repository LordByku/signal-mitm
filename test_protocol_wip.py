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
import time
from mitmproxy import ctx
from Crypto.Cipher import AES

DISC_BYTES =  b"\xFF"*32
MAC_LENGTH = 8

def current_milli_time():
    return round(time.time() * 1000)

def hex2PubKey(hexStr) -> X25519PublicKey:
    if ((hexStr[:2]) == "05"):
        hexStr = hexStr[2:]
    key = X25519PublicKey.from_public_bytes(unhexlify(hexStr))
    sanity = hexlify(key.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw)).decode()

    if hexStr.lower() != sanity:
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

def next(seed, bits):
    """
    Generate the next random number.

    As in Java, the general rule is that this method returns an int that
    is `bits` bits long, where each bit is nearly equally likely to be 0
    or 1.
    """

    if bits < 1:
        bits = 1
    elif bits > 32:
        bits = 32

    seed = (seed * 0x5deece66d + 0xb) & ((1 << 48) - 1)
    retval = seed >> (48 - bits)

    # Python and Java don't really agree on how ints work. This converts
    # the unsigned generated int into a signed int if necessary.
    if retval & (1 << 31):
        retval -= (1 << 32)

    return retval
    
def nextLong(seed):
    """
    Return a random long.

    Java longs are 64 bits wide, but the generator is only 48 bits wide,
    so we generate two 32-bit numbers and glue them together.
    """

    return (next(seed,32) << 32) + next(seed,32)

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
    # ctx.log.warn(
    #     "Their Mac: {} Our Mac: {} msg {} mac_key {}, senderIK {}, receiverIK {}".format(
    #         their_mac.hex(),
    #         our_mac.hex(),
    #         msg[:len(msg)-MAC_LENGTH],
    #         mac_key.hex(),
    #         PubKey2Hex(sender_IK),
    #         PubKey2Hex(receiver_IK)
    # ))
    
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
    def __init__(self, pre_key_id = 0, base_key = b'', identity_key = b'', message = b'', registration_id  = 0, signed_pre_key_id = 0):
        self.pksm = PreKeySignalMessage()
        self.pksm.pre_key_id = pre_key_id
        self.pksm.base_key = base_key
        self.pksm.identity_key = identity_key
        self.pksm.message = message # SignalMessage
        self.pksm.registration_id = registration_id
        self.pksm.signed_pre_key_id = signed_pre_key_id
    
    def getPrekeyID(self):
        return self.pksm.pre_key_id
    def getBaseKey(self):
        return self.pksm.base_key
    def getRegistrationID(self):
        return self.pksm.registration_id
    def getIdentityKey(self):
        return self.pksm.identity_key
    def getMessage(self):
        return self.pksm.message
    def getSignedPrekeyID(self):
        return self.pksm.signed_pre_key
    
    def setPrekeyID(self,id):
        self.pksm.pre_key_id = id
    def setBaseKeyID(self,id):
        self.pksm.base_key_id = id
    def setRegistrationID(self,id):
        self.pksm.registration_id = id
    def setIdentityKey(self,key):
        self.pksm.identity_key = key
    def setMessage(self,message):
        self.pksm.message = message
    def setSignedPreKeyID(self,signedPreKeyID):
        self.pksm.signed_pre_key_id = signedPreKeyID
    
    def SerializeToString(self):
        return self.pksm.SerializeToString()   
    def ParseFromString(self, msg):
        self.pksm.ParseFromString(msg)

def BuildSignalMessage(sender, text_message, profileKey=None, timestamp=None, counter=1, previous_counter=0):
    data_message = DataMessage()
    data_message.body = text_message
    ###### Stuff that you can get from the original message (and save the profile_key) or generate it your self 
    data_message.profileKey = profileKey
    data_message.timestamp = timestamp
    ######
    content = Content()
    content.dataMessage.CopyFrom(data_message)
    
    serializedContent = (content.SerializeToString())
    
    cipher, mac_key = sender.enc(serializedContent)
    print(f"[{sender.__class__.__name__}]\tSending ciphertext to {bob.__class__.__name__}:", b64(cipher))

    signalMessage = SignalMessage()
    signalMessage.ratchet_key = bytes.fromhex(PubKey2Hex(sender.DHratchet.public_key()))
    signalMessage.counter = counter
    signalMessage.previous_counter = previous_counter
    signalMessage.ciphertext = cipher
    
    return bytes.fromhex("32") + signalMessage.SerializeToString(), mac_key

def addMacSignalMessage(sender, receiver, sm, mac_key):        
    mac = compute_mac(sm, mac_key, sender.IK.public_key(), receiver.pubIK )

    sm = sm + mac 
    
    return sm
    
def BuildPreKeySignalMessage(sender, receiver, sm, pre_key_id, registration_id, signed_pre_key_id):
        
    preKeySignalMessage = PreKeySignalMessageClass(pre_key_id,
                                                sender.EK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                sender.IK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                sm,
                                                registration_id,
                                                signed_pre_key_id)

    pksm = bytes.fromhex("33") + preKeySignalMessage.SerializeToString()
    return pksm
    
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
    DHratchet: Optional[X25519PublicKey] = None
    
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
    uuid = ""
    new_DH_key = False
    last_DH_key = None
    
    def enc(self, msg: bytes) -> bytes:
        key, mac_key, iv = self.send_ratchet.next()
        key, mac_key, iv = self.send_ratchet.next()
        paddedContent = get_padded_message_body(msg)
        cipher = aes_256_cbc_encrypt(paddedContent, key, iv)
        return cipher, mac_key

    def dec(self, ctxt: bytes, pubkey: bytes):
        # receive the new public key and use it to perform a DH
        key, mac_key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = get_stripped_padding_message_body(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ctxt)))
        return msg, mac_key

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


    def recv(self, cipher, bob_public_key, pksm_flag = 0):
        if PubKey2Hex(bob_public_key) != PubKey2Hex(self.last_DH_key) or pksm_flag == 1:
            self.new_DH_key = True
            self.last_DH_key = bob_public_key
            self.dh_ratchet(bob_public_key)
        msg, mac_key = self.dec(cipher, bob_public_key)
        print(f"[{self.__class__.__name__}]\tDecrypted message:", msg)
        #DO IT HEREverify_mac(bytes.fromhex(mess), mac_key, hex2PubKey(ourIK),their_IK)

        self.last_person = False ##### TODO: ATtenzione nel caso in  cui si generi la stessa chiave due volte in DH_ratchet
        return msg, mac_key
        
    def send(self, other, msg):
        '''        
        sm, mac_key = self.BuildSignalMessage(self, msg, b"casual", current_milli_time(), counter=1, previous_counter=0)
        
        sm = self.addMacSignalMessage(sm, mac_key)
        
        preKeySignalMessage = PreKeySignalMessageClass(4917741,
                                                  self.EK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  self.IK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  sm,
                                                  6027,
                                                  13819045)

        pksm = bytes.fromhex("33") + preKeySignalMessage.SerializeToString()
        print(preKeySignalMessage.pksm)
        pksm1 = BuildPreKeySignalMessage(self, other, sm, 4917741, 6027, 13819045)
        
        wire_msg = base64.b64encode(pksm)'''
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
            #print(f"[{self.__class__.__name__}]\tRecv ratchet seed:", b64(sk.hex()))
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
        #print(sender_chain_root_key.hex(), sending_chain_chain_key.hex())
        #shared_send = self.root_ratchet.next(dh_send)[0]
        
        self.send_ratchet = SymmRatchet(sending_chain_chain_key)
        #print(f"[{self.__class__.__name__}]\tSend ratchet seed:", b64(shared_send))


class Alice(Human):
    def __init__(self, *args, **kwargs):
        # generate Alice's keys
        self.IK = kwargs.get("IK", X25519PrivateKey.generate())
        self.pubIK = kwargs.get("pubIK", self.IK.public_key() if self.IK is not None else None)

        self.EK = kwargs.get("EK", X25519PrivateKey.generate())
        self.pubEK = kwargs.get("pubEK", self.EK.public_key() if self.EK is not None else None)

        # Alice's DH ratchet starts out uninitialised
        self.DHratchet = None
        self.PublicDHratchet = None

class Bob(Human):
    def __init__(self, *args, **kwargs):
        # generate Bob's keys
        self.IK = kwargs.get("privIK", X25519PrivateKey.generate())
        self.pubIK = kwargs.get("pubIK", self.IK.public_key() if self.IK is not None else None)

        #self.IK = kwargs.get("IK", X25519PrivateKey.generate().public_key())
        
        self.SPK = kwargs.get("privSPK", X25519PrivateKey.generate())
        self.pubSPK = kwargs.get("pubSPK", self.SPK.public_key() if self.SPK is not None else None)
        
        self.OPK = kwargs.get("privOPK", X25519PrivateKey.generate())
        self.pubOPK = kwargs.get("pubOPK", self.OPK.public_key() if self.OPK else None)

        #self.OPK = kwargs.get("OPK",  X25519PrivateKey.generate().public_key())
        
        
        #self.DHratchet = kwargs.get("DH", X25519PrivateKey.generate())
        self.DHratchet = self.SPK
        self.PubDHratchet = self.pubSPK
        self.last_DH_key = self.DHratchet.public_key() if self.DHratchet else None

class Protocol:
    def __init__(self, alice: Alice= None, bob: Bob=None):
        self.alice = alice
        self.bob = bob
    
    def handshake(self):

        self.alice.x3dh(user2BobBundle(bob))
        self.bob.x3dh(user2BobBundle(alice))
        
    def BuildSignalMessage(self, sender, text_message, profileKey=None, timestamp=None, counter=1, previous_counter=0):
        data_message = DataMessage()
        data_message.body = text_message
        ###### Stuff that you can get from the original message (and save the profile_key) or generate it your self 
        data_message.profileKey = profileKey
        data_message.timestamp = timestamp
        ######
        content = Content()
        content.dataMessage.CopyFrom(data_message)
        
        serializedContent = (content.SerializeToString())
        
        cipher, mac_key = sender.enc(serializedContent)
        print(f"[{self.alice.__class__.__name__}]\tSending ciphertext to {self.bob.__class__.__name__}:", b64(cipher))

        signalMessage = SignalMessage()
        signalMessage.ratchet_key = bytes.fromhex(PubKey2Hex(sender.DHratchet.public_key()))
        signalMessage.counter = counter
        signalMessage.previous_counter = previous_counter
        signalMessage.ciphertext = cipher
        
        return bytes.fromhex("32") + signalMessage.SerializeToString(), mac_key

    def addMacSignalMessage(self, sm, sender, receiver, mac_key):        
        mac = compute_mac(sm, mac_key, sender.IK.public_key(),receiver.pubIK)
        print(len(mac))
        sm = sm + mac 
        
        return sm
        
    def BuildPreKeySignalMessage(self, sender, receiver, sm, pre_key_id, registration_id, signed_pre_key_id):
            
        preKeySignalMessage = PreKeySignalMessageClass(pre_key_id,
                                                  sender.EK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  sender.IK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  sm,
                                                  registration_id,
                                                  signed_pre_key_id)

        pksm = bytes.fromhex("33") + preKeySignalMessage.SerializeToString()
        return pksm

    def AliceSendToBob (self, sender, receiver, msg, profileKey, timestamp):
        
        sm, mac_key = self.BuildSignalMessage(sender, msg, profileKey, timestamp, counter=1, previous_counter=0)
        
        sm = self.addMacSignalMessage(sm, sender, receiver, mac_key)
        
        preKeySignalMessage = PreKeySignalMessageClass(4917741,
                                                  sender.EK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  sender.IK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  sm,
                                                  6027,
                                                  13819045)

        pksm = bytes.fromhex("33") + preKeySignalMessage.SerializeToString()
       # print(preKeySignalMessage.pksm)
        pksm1 = self.BuildPreKeySignalMessage(sender, receiver, sm, 4917741, 6027, 13819045)
        
        assert(pksm1==pksm)
        wire_msg = b64(pksm)
        #print(wire_msg)
################################################################
        '''       
        pksm_bytes = base64.b64decode(wire_msg)[1:]
        print(pksm_bytes.hex())
        pksm1 = PreKeySignalMessage()
        pksm1.ParseFromString(pksm_bytes)
        
        sm = SignalMessage()
        sm.ParseFromString(pksm1.message[1:-8])
        
        receiver.recv(sm.ciphertext, sender.DHratchet.public_key())
        self.last_person = True'''

        return wire_msg
    
class AliceToMitm(Protocol):
    def __init__(self, alice: Alice= None, bob: Bob=None):
        self.alice = alice
        self.bob = bob
    
    def handshake(self, alice_bundle):
        self.bob.x3dh(alice_bundle)
        self.bob.sk = ""
    
    def BobReceive (self, wire_msg):
        
        sm_bytes = base64.b64decode(wire_msg)[1:]
        pksm_flag = base64.b64decode(wire_msg)[0] == int("0x33", base=16)
        if (pksm_flag):
            pksm1 = PreKeySignalMessageClass()
            pksm1.ParseFromString(sm_bytes)
            AliceIK = pksm1.getIdentityKey()
            AliceEK = pksm1.getBaseKey()
            #ctx.log.error(AliceIK.hex())
            #ctx.log.error(AliceEK)
            self.alice = Alice(pubIK = hex2PubKey(AliceIK.hex()), pubEK = hex2PubKey(AliceEK.hex()))            
            alice_bundle = KeyBundle(IK=hex2PubKey(AliceIK.hex()), EK=hex2PubKey(AliceEK.hex()))
            #ctx.log.error(f"IK {PrivKey2Hex(self.bob.IK)}")
            #ctx.log.error(f"EK {PrivKey2Hex(self.bob.SPK)}")
            #ctx.log.error(f"OTK {PrivKey2Hex(self.bob.OPK)}")
            self.handshake(alice_bundle)
            sm_bytes = pksm1.getMessage()
        else:
            assert(base64.b64decode(wire_msg)[0] == int("0x32", base=16))
        
        sm = SignalMessage()
        sm.ParseFromString(sm_bytes[1:-8])
        #ctx.log.error(sm)
        DHratchet = hex2PubKey(sm.ratchet_key.hex())
        self.alice.PublicDHratchet = DHratchet
        ctxt = sm.ciphertext
        
        msg, mac_key = self.bob.recv(ctxt, DHratchet, pksm_flag) ##### non usare recv cosi ma magari modificarlo un minimo
        #ctx.log.warn(verify_mac(sm_bytes, mac_key, self.alice.pubIK, self.bob.pubIK))
        #ctx.log.warn(f"Mac key {mac_key.hex()}")
        return msg

    def BobSend(self, msg, profileKey = b"Casual",  timestamp = current_milli_time()):
        
        sm, mac_key = self.BuildSignalMessage(self.bob, msg, profileKey, timestamp, counter=1, previous_counter=0)
        print(f"Before {sm.hex()}")
        sm = self.addMacSignalMessage(sm, self.bob, self.alice, mac_key)
        print(f"After {sm.hex()}")
        
        # ctx.log.warn(f"self.bob.IK {PubKey2Hex(self.bob.pubIK)}")
        # ctx.log.warn(f"self.alice.IK {PubKey2Hex(self.alice.pubIK)}")
        # ctx.log.warn(f"mac_key {mac_key.hex()}")
        wire_msg = sm
        
        return wire_msg
    
class MitmToBob(Protocol):
    def __init__(self, alice: Alice= None, bob: Bob=None):
        self.alice = alice
        self.bob = bob
    
    def handshake(self, bob_bundle):
        self.alice.x3dh(bob_bundle)
        self.alice.sk = ""
    
    def AliceReceive (self, wire_msg):
        sm_bytes = base64.b64decode(wire_msg)
        pksm_flag = base64.b64decode(wire_msg)[0] == int("0x33", base=16)
        if (pksm_flag):
            sm_bytes = sm_bytes[1:]
            pksm1 = PreKeySignalMessageClass()
            pksm1.ParseFromString(sm_bytes)
            BobIK = pksm1.getIdentityKey()
            BobEK = pksm1.getBaseKey()
            #ctx.log.error(pksm1)
            self.bob = Bob(pubIK = X25519PublicKey.from_public_bytes(BobIK), pubEK = X25519PublicKey.from_public_bytes(BobEK))            
            bob_bundle = KeyBundle(IK=X25519PublicKey.from_public_bytes(BobIK), EK=X25519PublicKey.from_public_bytes(BobEK))
            self.handshake(bob_bundle)
            sm_bytes = pksm1.getMessage()
        else:
            assert(base64.b64decode(wire_msg)[0] == int("0x32", base=16))
        
        sm = SignalMessage()
        sm.ParseFromString(sm_bytes[1:-8])
        
        DHratchet = hex2PubKey(sm.ratchet_key.hex())
        self.alice.PublicDHratchet = DHratchet
        ctxt = sm.ciphertext

        msg, mac_key = self.alice.recv(ctxt, DHratchet, pksm_flag) ##### non usare recv cosi ma magari modificarlo un minimo
        print(verify_mac(sm_bytes, mac_key, self.bob.pubIK, self.alice.pubIK))


        return msg

    def AliceSendSignalMessage(self, msg, profileKey = b"Casual",  timestamp = current_milli_time()):
        
        sm, mac_key = self.BuildSignalMessage(self.alice, msg, profileKey, timestamp, counter=0, previous_counter=0)
        sm = self.addMacSignalMessage(sm, self.alice, self.bob, mac_key)
        
        wire_msg = base64.b64encode(sm)
        
        return wire_msg
    
    def AliceSendPreKeySignalMessage(self, msg, profileKey = b"Casual",  timestamp = current_milli_time()):
        sm, mac_key = self.BuildSignalMessage(self.alice, msg, profileKey, timestamp, counter=1, previous_counter=0)
        
        sm = self.addMacSignalMessage(sm, self.alice, self.bob, mac_key)
        
        preKeySignalMessage = PreKeySignalMessageClass(4917741,
                                                  self.alice.EK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  self.alice.IK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                                  sm,
                                                  6027,
                                                  13819045)

        pksm = bytes.fromhex("33") + preKeySignalMessage.SerializeToString()
        
        return pksm

if __name__ == "__main__":
    alice, bob, mitmA, mitmB = Alice(), Bob(), Bob(), Alice()
    alice_bundle, bob_bundle, mitmA_bundle, mitmB_bundle = user2Bundle(alice), user2Bundle(bob), user2Bundle(mitmA), user2Bundle(mitmB)
    
    ############### Hidden
    alice.x3dh(mitmA_bundle)
    sm, mac_key = BuildSignalMessage(alice, b"hey bob, how you doin'?", b"alice profileKey", current_milli_time())
    sm = addMacSignalMessage(alice, mitmA, sm, mac_key)
    pksm = BuildPreKeySignalMessage(alice, mitmA, sm, 1, 2, 3)
    ###############
    
    #### Alice to Mitm 
    wire_msg = b64(pksm)
    atm = AliceToMitm(bob = mitmA)
    dec_msg = atm.BobReceive(wire_msg)
    print(dec_msg)
    
    #############  Mitm send to Bob
    mitmB.x3dh(bob_bundle)
    bob.x3dh(mitmB_bundle) ### HIDDEN
    mitmToBob = MitmToBob(alice = mitmB, bob = bob)
    msg_to_bob = mitmToBob.AliceSendSignalMessage(b"hey bob, you are dumb")

    #############
    msg_to_bob = base64.b64decode(msg_to_bob)
    
    bob_sm = SignalMessage()
    bob_sm.ParseFromString(msg_to_bob[1:-8])
    print(msg_to_bob.hex())
    
    msg, mac_key = bob.recv(bob_sm.ciphertext, X25519PublicKey.from_public_bytes(bob_sm.ratchet_key[1:]))
    print(verify_mac(msg_to_bob, mac_key, mitmToBob.alice.pubIK, bob.pubIK))

    sm, mac_key = BuildSignalMessage(bob, b"fuck you alice", b"bob profileKey", current_milli_time())
    sm = addMacSignalMessage(bob, mitmB, sm, mac_key)
    
    wire_msg2 = b64(sm)
    ################
    mitmToBob.AliceReceive(wire_msg2)
    
    msg= atm.BobSend(b"fuck you alice", b'bob profile key')
#   msg = base64.b64decode(msg)  
    ################ hidden
    alice_sm = SignalMessage()
    alice_sm.ParseFromString(msg[1:-8])
    #print(alice_sm)
    
    msg1, mac_key = alice.recv(alice_sm.ciphertext, X25519PublicKey.from_public_bytes(alice_sm.ratchet_key[1:]))
    print(verify_mac(msg, mac_key, atm.bob.pubIK, atm.alice.pubIK))
    ###############
'''
    # Alice performs an X3DH while Bob is offline, using his uploaded keys
    #alice.x3dh(bob_bundle)
    alice.x3dh(mitmA_bundle)

    # Bob comes online and performs an X3DH using Alice's public keys (IK, EK)
    #bob.x3dh(alice_bundle)
    
    #assert(alice.sk==bob.sk)

    # Initialize their symmetric ratchets
    #alice.init_ratchets()
    #bob.init_ratchets()

    # Print out the matching pairs (debug)
    # Initialise Alice's sending ratchet with Bob's public key
    #alice.dh_ratchet(bob.DHratchet.public_key())

    # Alice sends Bob a message and her new DH ratchet public key
    #alice.send(bob, b"Hello Bob!")

    # Bob uses that information to sync with Alice and send her a message
    #bob.send(alice, b"Hello to you too, Alice!")

    #alice.send(bob, b"Do you like Pizza?")

    ## From this point forward the code fucks up.
    ## TODO @andrea - figure it out
    ## Figure it out with multiple messages from one party

    #alice.dh_ratchet(bob.DHratchet.public_key())
    #bob.send(alice, b"Hic sunt leones")
    #alice.send(bob, b"Let's do crime")
    #print(alice.last_person)
    #bob.send(alice, b"Si!")
    #bob.dh_ratchet(alice.DHratchet.public_key())

    #bob.send(alice, b"HELL YEAH!!!")
    #print(alice.last_person)
    #print(bob.last_person)
    
    #alice.send(bob, b"Cosa succede?")
    prot = Protocol(alice,bob)
    wire_msg = (prot.AliceSendToBob(alice, mitmA, b"heyyyyy", b'casual', current_milli_time()))

    
    aliceToMitm = AliceToMitm(bob=mitmA)
    
    dec_msg = aliceToMitm.BobReceive(wire_msg)
    
    mitmB.x3dh(bob_bundle)
    bob.x3dh(mitmB_bundle)
    wire2 = prot.AliceSendToBob(mitmB, bob, b'fuck bob', b'Not so casual', current_milli_time())
    MitmToBob = AliceToMitm(bob = mitmB, alice = bob)
    MitmToBob.BobSend(wire_msg)
    
    relayed = Content()
    relayed.ParseFromString(dec_msg)
    print(type(relayed.dataMessage.profileKey))
    mess_to_bob = base64.b64decode(MitmToBob.BobSend(msg=b"fuck bob", profileKey=relayed.dataMessage.profileKey, timestamp=current_milli_time()))
    
    bob_sm = SignalMessage()
    print(f"MAcarena {mess_to_bob.hex()}")
    bob_sm.ParseFromString(mess_to_bob[1:-8])
    print(f"ELla madonna {mess_to_bob.hex()}")
    
    msg, mac_key = bob.recv(bob_sm.ciphertext, X25519PublicKey.from_public_bytes(bob_sm.ratchet_key[1:]))

    message_to_alice = base64.b64decode(aliceToMitm.BobSend("bob received"))

    alice_sm = SignalMessage()
    alice_sm.ParseFromString(message_to_alice[1:-8])
    print(f"ELla madonna {message_to_alice.hex()}")
    
    msg, mac_key = alice.recv(alice_sm.ciphertext, X25519PublicKey.from_public_bytes(alice_sm.ratchet_key[1:]))

    #verify_mac(message_to_alice, mac_key, bob.pubIK, alice.pubIK)
    
    MitmToBob =  AliceToMitm()'''
    
