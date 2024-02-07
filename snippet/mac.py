import hmac, hashlib, base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from binascii import hexlify,unhexlify
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
from proto_python.WebSocketResources_pb2 import *
from proto_python.SignalService_pb2 import *
from test_protocol_wip import *

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

sk = bytes.fromhex("ad5e4d499c0dea8eae9f557ec5196804f1a8b15c0a7a26a6e33c5bdcfdce27f6faf21845a3a61448f8f2fea6d928c8c5472f66bc80c54591a600750163b5c1d2")

root_key, chain_key = sk[:32], sk[32:]

DHratchet = hex2PrivKey("187d54327d675dfc283b28d34fffbb09158cda316df079cd2d84f5928a94de7e")

other_pub_DH= hex2PubKey("055f2881bf305778e1221d4f4e83eebfa863f04b6879c6f0e109207bbcd8e1d00e") ### todo
dh_send = DHratchet.exchange(other_pub_DH)
sk = hkdf(dh_send, 64, root_key, b"WhisperRatchet")
sender_chain_root_key, sending_chain_chain_key = derive_keys(sk)

print(sender_chain_root_key.hex(),sending_chain_chain_key.hex())

print(DHratchet.public_key().public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw).hex())

proto_buf = "080112a3060a03505554123d2f76312f6d657373616765732f65376437316165612d633431612d346438382d383536622d3032653937393938383633613f73746f72793d66616c73651ab3057b2264657374696e6174696f6e223a2265376437316165612d633431612d346438382d383536622d303265393739393838363361222c226d65737361676573223a5b7b22636f6e74656e74223a224d776a746b367743456b49774e545a684e446b355a4445304f445a6d4f444e695a44517a596d517a595745795a445931597a63324d4751354f5459354e575534595756695a6d4e6b4e4441324e6d526a4e54526c5a6a4d784e6a457a4e546b774e445561516a41315a44526d4e6a51325a5751315a474e6c597a466b4f546c684d324a6d5957566b4d4445314d5467305a6a49354e6d45794d54457a596d4e6b4d325a6d4d4449334d6a526c4d5449344d6d49315a6a526a4f44453059534c5441544d4b49515753485a346d4f424f3037524b646671542f59474741366a5265455875474b6430424d674f796156586544784141474141696f41464a3543645372596f554c4b3434794f796d6c77636d342b71522f746a4645304377363133304d7754305837422f70727632472b67562f58556d6e383159437a7a622f7655354549472b533168413335663441385269582b4a704f75795a592f316f556c70556e30385a384a654a776c334732526857684f3367523457674f7a4b685868386f744f4e756f334348497a794e63596c456a3268476e466e2f6d442f5032472f4332696d73765a684c642f6e68493067505932787766674965394d2f493451454f4f4231554757734e6749377642557463577a697a656b77664775556f6979387770626e4c42673d3d222c2264657374696e6174696f6e4465766963654964223a312c2264657374696e6174696f6e526567697374726174696f6e4964223a383232372c2274797065223a337d5d2c226f6e6c696e65223a66616c73652c2274696d657374616d70223a313639343532313033393332372c22757267656e74223a747275657d20f4ffbdb8b8d3ca87442a1d636f6e74656e742d747970653a6170706c69636174696f6e2f6a736f6e"

WebSocketMessage = WebSocketMessage()

WebSocketMessage.ParseFromString(bytes.fromhex(proto_buf))
print(WebSocketMessage)

chain = SymmRatchet(bytes.fromhex("46ef1cdff997732c678c8fc11734ff3ce9299f75b0908fb0ebd11b57aa8eeb16"))

a,b,c = (chain.next())
a,b,c = (chain.next())


print(a.hex(),b.hex(),c.hex())
