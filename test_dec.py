ourPrivIK = "4005F36EF1899CA47B848725919E8DE2E988A1FF3E98C5B094EB14B701EC8C5E"
ourIK = "05FCEB87526F2C5E039A8C222F60BDCC8AE18027256CE5914F38F646B1C1B0FA76"

their_IK="05720D601D23BB6C4274CB0064FECFDFA221BB0B8CB659C4A8A6600EBC34E49862"
their_SPK="05CD704316FFDC3AEF68028E4542B37D51CB16A81DDBD597E03CF7CB2AA09DCF7B"
their_OTK="0538461224A6C32CC29DAF7D5736E7BBD019B6018A35ED14CE6A8A30F5F87ED74E"

ourPrivEK = "d0ace348e93444aa69501d12c38274da2ecbc391658bb13697fd35cfc5feb142"
ourEK = "055304ce7392bfc42c41ab41205bcd2aba5dea3e3cf1dfb754d166bb020e530950"

#chainValue = bytes.fromhex("22514de32b147bdfd03ec2400d6de7341e99c03bb92f638d2944147aa4120f62")



from base64 import b64decode
from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from test_protocol import *
from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
     
#ctxt = b64decode("SERDgrF7I0TolKExiiMH67IsQ8Vir6WDr7DUDWc/O74blhiVlJKOA68K9b/1IlMlx1eibdWpX2DV+MkF/sNe9YCPy9qgZmULTiXPcdXt/NDm6maNLn2jbYWTZo5aXMNExc3sfQukcmTtiTfoVuyFL3aQ7Df0ADM6JWVBIm+a3/8VV0B+bNkAFxAEy3fF5PxJ0jbpnVKugWltlU/kXdGD8A==")

ctxt = bytes.fromhex("4052e1c87e68ec8bfa64b4f0d74ed59bf43878e36245350e52f6e363577d09f9122ffe3d042fc5570b5bfc60c24aad73fff78a7583b547342481ca07a300abc8ce00695212e8a896bee11ffa40d53a0acd1f0af74b05842ca99c0544af0b59d7008cb1fdda2973b32365dad1472ced957daf9faa3d7f024737b273f4e41222b1a864505326beb53575eda44b47feaf1b2fadb2eca4e356c734d0a6e5bcfec632")

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
    hexStr = "05" + pubKey.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw).hex()
    sanity = X25519PublicKey.from_public_bytes(hexStr)

    return hexStr

def PrivKey2Hex(privKey: X25519PrivateKey) -> str:
    hexStr = privKey.private_bytes(encoding=Encoding.Raw,format=PrivateFormat.Raw).hex()
    sanity = X25519PrivateKey.from_private_bytes(hexStr)
    
    return hexStr


ourPrivEK = hex2PrivKey(ourPrivEK)
# print(ourEK[2:])
# print("====")
#pk = ourPrivEK.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
ourPrivIK = hex2PrivKey(ourPrivIK)

ourEK = hex2PubKey(ourEK)
their_IK = hex2PubKey(their_IK)
their_SPK = hex2PubKey(their_SPK)
their_OTK = hex2PubKey(their_OTK)

def send_message_check():
    alice = Alice(IK = ourPrivIK, EK = ourPrivEK)
    #bob = Bob(IK = their_IK, SPK = their_SPK, OPK = their_OTK)

    alice_bundle = user2AliceBundle(alice)
    #bob_bundle = user2BobBundle(bob)

    bob_bundle = KeyBundle(
            their_IK,
            their_SPK,
            their_OTK
            #'EK': usr.EK if hasattr(usr, 'EK') else None
    )

    ## DH handshake

    from controllo import hkdf, SymmRatchet, unpad, hmac_sha256
    from Crypto.Cipher import AES

    alice.x3dh(bob_bundle)

    root_key, chainValue = derive_keys(alice.sk)

    alice.init_ratchets()

    print(root_key.hex(),chainValue.hex())
    # create chain // dh_ratchet


    #sending_ratchet_key = hex2PrivKey("187d54327d675dfc283b28d34fffbb09158cda316df079cd2d84f5928a94de7e")

    #alice.DHratchet = sending_ratchet_key
    alice.dh_ratchet(their_SPK)

    #dh = sending_ratchet_key.exchange(their_SPK)
    #sk = hkdf(dh, 64, root_key, b"WhisperRatchet")

    #alice.DHratchet = sending_ratchet_key
    #alice.dh_ratchet(their_SPK)

    #sender_chain_root_key, sending_chain_chain_key = derive_keys(sk)

    #print(f"sender_chain_root_key: {hexlify(sender_chain_root_key).decode()}, sending chain chain key {hexlify(sending_chain_chain_key).decode()}")


    def dec(self, ctxt: bytes, pubkey: bytes) -> bytes:
        # receive the new public key and use it to perform a DH
        self.dh_ratchet(pubkey)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ctxt))
        return msg


    cipher_key, mac_key, iv = alice.send_ratchet.next()

    mess = "330a2105921d9e263813b4ed129d7ea4ff606180ea345e117b8629dd013203b26955de0f1000180022a0014052e1c87e68ec8bfa64b4f0d74ed59bf43878e36245350e52f6e363577d09f9122ffe3d042fc5570b5bfc60c24aad73fff78a7583b547342481ca07a300abc8ce00695212e8a896bee11ffa40d53a0acd1f0af74b05842ca99c0544af0b59d7008cb1fdda2973b32365dad1472ced957daf9faa3d7f024737b273f4e41222b1a864505326beb53575eda44b47feaf1b2fadb2eca4e356c734d0a6e5bcfec632f9f263e73db438dc"


    verify_mac(bytes.fromhex(mess), mac_key, hex2PubKey(ourIK),their_IK)

    '''
    mac = hmac.new(key=mac_key,msg=None,digestmod=hashlib.sha256)
    mac.update(b"\x05" + hex2PubKey(ourIK).public_bytes(Encoding.Raw, PublicFormat.Raw))
    mac.update(b"\x05" + their_IK.public_bytes(Encoding.Raw, PublicFormat.Raw))
    mac.update(bytes.fromhex(mess[:len(mess)-16]))
    print(mess[len(mess)-16:])
    '''

    #print(f"MAC DIGEST : {mac.hexdigest()[:16]}")
    #print(f"MAC : {ctxt[-8:].hex()}")

    print(f"cipher_key: {cipher_key.hex()}, iv: {iv.hex()}")

    #chainValue = bytes.fromhex(hmac_sha256((chainValue), b'\x02'))
    #chainValue = hmac_sha256((chainValue), b'\x02')

    #print(chainValue, "----")
    print(len(ctxt))
    msg = get_stripped_padding_message_body(unpad(AES.new((cipher_key), AES.MODE_CBC, iv).decrypt(ctxt)))
    print(msg, msg.hex())
    print(alice.send_ratchet.state)
    #print(alice.chainValue.state)
    
    content = Content()
    
    content.ParseFromString(msg)
    
    print(content)

def recv_mess():
    pass

send_message_check()