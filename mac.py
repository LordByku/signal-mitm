import hmac, hashlib, base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from binascii import hexlify,unhexlify
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
from proto_python.WebSocketResources_pb2 import *
from proto_python.SignalService_pb2 import *

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

MAC_LENGTH = 8

def verify_mac(msg:bytes, mac_key: bytes, sender_IK: X25519PublicKey, receiver_IK: X25519PublicKey):
    
    our_mac = compute_mac(msg[:len(msg)-MAC_LENGTH], mac_key, sender_IK, receiver_IK)
    their_mac = msg[len(msg) - MAC_LENGTH : ]
    
    
    result = our_mac == their_mac
    if not result:
        # A warning instead of an error because we try multiple sessions.
        print(
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



bob_IK = hex2PubKey("055cb84ea241d496fddd2373a431c89d24717365c3d18071515214c1d73afb230b")

alice_IK = hex2PubKey("05a442976081395f68c96f5f81a83529a573f6813a0ae04dce493c03d1e78af606")

mac_key = bytes.fromhex("a20945cd0bcd80d94a617e20219f26509b84d556a5774070492677feed2a7a3b")
msg = bytes.fromhex("320a2105f68cd5c3100513962b318826d4059eabe8ac4b99f8b001903c5d677395f69b7b1001180022a0018936e56aa0542914856034893fced21baa414144c6d3a3f70b099a074c74f6e3efe0c3baf4b14c89a18b62f5dc79e1d9f42659a3d9ebd4ade95de6224addfc8784f648125ca400a10f2276ece6bb4450e6000abd7a7a11a908f4e30ea7595906bfe12422907908b28a79d6ff4b18ad55549c6c49793885729cc33e304e4b65dee4c2764a1b8a809ca0843e7d1aa91e6afc02a73ce5d7331141cb44b3cd4db3575cb1a6026c7c2f33")
print(verify_mac(msg, mac_key, bob_IK, alice_IK))



