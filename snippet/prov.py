from binascii import unhexlify
from base64 import b64decode, b64encode
from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from test_protocol import *
import time

from protos.gen.wire_pb2 import *
from protos.gen.SignalService_pb2 import *
from protos.gen.storage_pb2 import *
from protos.gen import *
import test_protocol

padder = padding.PKCS7(256).padder()

eph1 = "4066affebbdbf2781691508ce62dfb6ff6df5c1ce10b5dfa1e0f1b5f8fb51659"

eph2 = "d0ace348e93444aa69501d12c38274da2ecbc391658bb13697fd35cfc5feb142"



ratchet = "6e43718b731532df7125fef2833d9814af220b2fad5c55b9b320b68d1306f446"
ratchet2 = "fccb68f7fc2963ccf007d99aada7fabd5e4b12cc213feb2f7efd3ff55f833602"
ratchet3 = "187d54327d675dfc283b28d34fffbb09158cda316df079cd2d84f5928a94de7e"

ourPrivIK = "4005F36EF1899CA47B848725919E8DE2E988A1FF3E98C5B094EB14B701EC8C5E"
ourIK = "05FCEB87526F2C5E039A8C222F60BDCC8AE18027256CE5914F38F646B1C1B0FA76"

ourPrivEK = "d0ace348e93444aa69501d12c38274da2ecbc391658bb13697fd35cfc5feb142"
ourEK = "055304ce7392bfc42c41ab41205bcd2aba5dea3e3cf1dfb754d166bb020e530950"

PrivSPK = "a07a15a8e971e25a04c790d862956ec463e0bc93292808cc014ac46d7f4a36cd"
PublSPK = "05ed1148675457930f87e4beaf9ea41001a512ec826a15c9b52e291150d318280a"
PrivIK =  "56f5b16e68931615b1a476b39b915633e3db186d0589dc0c3ca31ac593c757a6"
PublIK =  "059722606d0db4ec6a1c361fda3d980f690eaf83c77f412dd1bd21fdb5a8915410"
PrivOTK = "08a47709d311f94e8137066057eb328d9dd9b8c58563997780849b6c056cf2a4"
PublOTK = "05ed1148675457930f87e4beaf9ea41001a512ec826a15c9b52e291150d318280a"

a = test_protocol.hex2PrivKey("9b301145d87ad4a2530ed25a3ec72373e61be3f56cf1693268bc59b1da69130d")

pub_a = a.public_key()

print(hex2PubKey(pub_a.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()))

input()
    
def generateBob():
    BobSPK = Ed25519PrivateKey.generate()
    print(f"PrivSPK = " + BobSPK.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    print(f"PublSPK = " + PubKey2Hex(BobSPK.public_key()))
    
    BobIK = Ed25519PrivateKey.generate()
    print(f"PrivIK = " + BobIK.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    print(f"PublIK = " + PubKey2Hex(BobIK.public_key()))
    
    BobOTK = Ed25519PrivateKey.generate()
    print(f"PrivOTK = " + BobOTK.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    print(f"PublOTK = " + PubKey2Hex(BobSPK.public_key()))
    
    return BobIK, BobSPK, BobOTK
    
#generateBob()

####### padding done here is for hiding the length
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

    for i in range(len(message_with_padding) - 1, -1, -1):
        if message_with_padding[i] == 0x80:
            padding_start = i
            break
        elif message_with_padding[i] != 0x00:
            print("Padding byte is malformed, returning unstripped padding.")
            return message_with_padding

    stripped_message = message_with_padding[:padding_start]

    return stripped_message

def aes_256_cbc_encrypt(ptxt, key, iv):
    ptxt = padder.update(ptxt) + padder.finalize()
    #print(f"PADDED {ptxt}")
    #print(len(ptxt))
    msg = AES.new((key), AES.MODE_CBC, iv).encrypt(ptxt)
    
    return msg


alice = Alice(IK = hex2PrivKey(ourPrivIK), EK = hex2PrivKey(ourPrivEK))
bob = Bob(privIK = hex2PrivKey(PrivIK), privSPK = hex2PrivKey(PrivSPK), privOPK = hex2PrivKey(PrivOTK))

alice_bundle = user2Bundle(alice)

bob_bundle = user2Bundle(bob)

alice.x3dh(bob_bundle)
bob.x3dh(alice_bundle)

alice.init_ratchets()
bob.init_ratchets()

alice.dh_ratchet(bob.SPK.public_key())

def ping():   
    cipher_key, mac_key, iv = alice.send_ratchet.next()
    
    body = "Hello World"
    profileKey = bytes.fromhex("8dc269f19ba50711fba549653b59fc4e36bfd1b1629ea043e452ebc44e2b7c51")
    timestamp = int(time.time())
    
    data_message = DataMessage()
    data_message.body = body
    data_message.profileKey = profileKey
    data_message.timestamp = timestamp
    
    content = Content()
    #print(data_message)
    content.dataMessage.CopyFrom(data_message)
    
    serializedContent = (content.SerializeToString())

    paddedContent = get_padded_message_body(serializedContent)
    #print(paddedContent,len(paddedContent))
    
    msg = aes_256_cbc_encrypt(paddedContent, cipher_key, iv)
    
    print(msg, len(msg))
    
    signalMessage = SignalMessage()
    signalMessage.ratchet_key = bytes.fromhex(PubKey2Hex(alice.DHratchet.public_key()))
    signalMessage.counter = 1
    signalMessage.previous_counter = 0
    signalMessage.ciphertext = msg
    
    sm = bytes.fromhex("33") + signalMessage.SerializeToString()
    
    mac = compute_mac(sm, mac_key, hex2PubKey(ourIK),hex2PubKey(PublIK) )
    sm = sm + mac
    
    #print(sm.hex())

    preKeySignalMessage = PreKeySignalMessage()
    preKeySignalMessage.pre_key_id = 4917741
    preKeySignalMessage.base_key = bytes.fromhex(ourEK)
    preKeySignalMessage.identity_key = bytes.fromhex(ourIK)
    preKeySignalMessage.message = sm # SignalMessage
    preKeySignalMessage.registration_id = 6027
    preKeySignalMessage.signed_pre_key_id = 13819045
    
    pksm = bytes.fromhex("33") + preKeySignalMessage.SerializeToString()
        
    wire_msg = b64encode(pksm)
    
    print(wire_msg)
    
    ######################################################################
    
    bob.dh_ratchet(alice.DHratchet.public_key())
    print(type(bob.recv_ratchet.state))
    key, mac_key, iv = bob.recv_ratchet.next()
    
    bobMsg = get_stripped_padding_message_body(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(msg)))
    print(bobMsg)
    
    bobContent = Content()
    
    bobContent.ParseFromString(bobMsg)
    
    print(bobContent)
    
    
ping()

