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

from test_protocol_wip import *
from protos.gen.wire_pb2 import *
from protos.gen.SignalService_pb2 import *
from protos.gen.storage_pb2 import *
     
#ctxt = b64decode("SERDgrF7I0TolKExiiMH67IsQ8Vir6WDr7DUDWc/O74blhiVlJKOA68K9b/1IlMlx1eibdWpX2DV+MkF/sNe9YCPy9qgZmULTiXPcdXt/NDm6maNLn2jbYWTZo5aXMNExc3sfQukcmTtiTfoVuyFL3aQ7Df0ADM6JWVBIm+a3/8VV0B+bNkAFxAEy3fF5PxJ0jbpnVKugWltlU/kXdGD8A==")
ctxt = bytes.fromhex('e54fb3dd127012e220b674a65257163d23ce418a6bb70209ac7d13f3d68de8abe85959cc55dfa24c97373a42aca5af3685592e89e807998771b9e046def8ad1a8cdeb355ba10b9e22c3a124ec279fd91dc5adbd760c4bb685810933cb7ae4e694c33b226e359b6bc34e1ddee020674c7169e4fa53ac972199296a2293f50249861f37ca90f0ef9b6d17e464f39bfde16f1c906a8f220db4d3d1f98d3b67fd2bd3620bdbfd8fcee2e806a2c1451a0562e55e6ca03964132593196ef39ad09ea360d3bb28dab8e91fcf83cc7282a4569453fec9363cca85ee85e180013fd06314d4e320967567538cd95434c7dce4b1946f889cabe91709cbb5e47bb03f5d44b4abcb3387693edaab82293d33e9c0e1d0512552564e0deb0770657575f7ed6a5b7bfd8afe568ec45aa937882cc55f7a8c528628320ec57b341b5a367731bdd98785805de2b8374775c0cce52b5143b5033d3e30d497414ef873dc9343aa8c7dbd4360b3b68f463fea3637422f234b5069de0f25c23b97a059aa36a51fde9ecb8adb331cbfe14bc9c80d163118f493d4bb1518ca037610c5f9a9ebdf6dc4132bfa29ea4c8a251e5fd99b9c6c6f17ff88ce3f88881baaa1e05d02bc59b28c8737f9603cd337ae1142af7d0b3f24c0d1a55363b95df9579d21dd027c5d1d8fb81ef6ec5d64b8c2ac620d639c368d3dfe7134d')
def next(state, inp=b""):
    # turn the ratchet, changing the state and yielding a new key and IV
    msg_kdf = hmac_sha256((state), b'\x01')
    msg_key = hkdf(bytes.fromhex(msg_kdf), 80, None, b"WhisperMessageKeys")
    
    cipher_key = msg_key[0:32]
    mac_key =  msg_key[32:64]
    iv = msg_key[64:]

    state = bytes.fromhex(hmac_sha256(state, b'\x02'))
    
    return cipher_key, mac_key, iv
send_key = "a70d58ba3d67f2b44fe62809a91451057ba44a38413d835b1e418d52c529f86c"
#send_key = "6390ba37ef56abb140655d0093bb165745bd731ace00c402590302ec8bef1d30"
key,mac_key,iv, = next(bytes.fromhex(send_key))
print(key.hex(),mac_key.hex(),iv.hex())

#a= b'\x11\n!\x05\x8d\xe2p\xff\x04\xe3\xa6\x1d\x13\xf2_`=\xe9\xb6\x10\xc0\x9es\'\x9cE\xf9\xb3ww\n\x95\x1a\x17\x80o\x12+;\x05\\3-_8\x13\xc9\\j\xd4\r>EX\xd1\x9am\xba\'\x89\x14g)\xb8\t\x80\x97;\xab\x02+\x940@\xe1\xc2\xa2\xc8\x08;%\x1a\xf9\x03\x0c\xdb\xc8IN\xccg<\xd9\xca\xa31\xd8\xc7\xb0=^\xb9\x15\xc3\x97\xb6\xff!\xb6\\k\x08\xb9\xa84n\xd4\xe0(\xfa$dXw\x05:\xbb\x81~\x15\xa2j\x0b\xe9\xcb\xeb\xf4\x85\x13\xd3\xac\x13L\xcc\x93\xfa\x887\n\xebp\xc8\xb1\xc1\xd7\xa5\xd8\x8b\x8b\x83\x9e\xc4^\x836\xff\x8c\x92\xbc5H\xf5\xcb\xdaW\\\xe5\x94\xaaG\x0cd\xab{s`\xa0\x8dE\xb0\x1fiB\x9b\xb0\xddG7$j\xb8\xbe\xcc\xce\xc1\x00\x17\xc8\xdc\xe5M\xf9+/kD\xb38E\xd4[\x9b\x04\x83\xe47Qu\x9c\x19\x82\xa5\xadX^\xb2i\x01\xd58\x9d\xfan\xbc\xc9`\xd3sc)\x06\x8e^^=\x81\x04r\xc8\x84\x10\xe64y\xb8\xaf\xeb\xd1c4\x9c\xcc\xd5\xbcL"\x8a%\xddC\xa1\x19\xb9l\xef[#\x050\xfc\xb8\x1a\xe3\x7f\x84*;A\xc0\xf2\xd8E\x829\xfbh\x0b\xbc\x8f\x94\x8b\tp\x82I\xa2\xack_\x18\xe3\x80G8\xc2\x8f:\x8a\x91|\xa8\x14&\xf6\xdf\xdd\xdb\x10\x04\x027\xce\xd2}\xb3\x8a\'W14Y\xdfa\xcf\x8e\xe3\xcb\x82\x1a\x90*\xc3\xdeM\xc9\x9f\x88a\\\x7f\r$\xbf(\x14_\xadF\xb3\xc4v\xadCX\x12u\xdd\x9bA\xd2Hod\xacEh\xfd\x95\xdb\xda\xf1\xdb07\x8au=\x98M-\xe2\x03\x9d\xc8t|88\xb57\xdf\x06\x99\xb1vWViL\x91I\xcfR6\x86\x0fB\x8d\xc1\x81!\xec\x85\xe4"\xa6|\xfc\x815\x80\x886!\x7f\xce\xb1\x18\xeeeOd\xb9\x0c\xabI\xb5\'k\xdd\x95\x0e\xe5^\xb5\xb5\xa9c+tV\xdb\xe9P\x8ao\x9dO\xac\xb0lp\x9c\x12@\x9b\xd1\x8c\xf88\x94M\xcd\xc0Q\xccLZmbj=\x96\xabRgWd\x18\xdd\x93zzzPD@\xa5w0\x9f\x0cx\x87X\x12\xe4<,\xa4\x19\xe9\xfc@\xe7\xd7c\n\xae\xd1\xed\xa1\xe3\xdd\r\xe8C\xe1\xa8\xa7\xceO;\xc0\xbf\x1e\xd1\x16\x81\xa1\x86\x89\xe6\xc0A*\x88[\xe4P(\xd0\xe2\xc0VG\t\xea6'

msg = (AES.new(key, AES.MODE_CBC, iv).decrypt(ctxt))
print(msg.hex())
exit()


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