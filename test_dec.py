ourPrivIK = "704E4AD1D72628D9EC6152F000289A8C808119AAAEBE797AB40778DF31FE6B7D"
ourIK = "05F4CC1016AA947573B3A0E8C3AC9EF6C2DFB03F7B34A5F1FEC7664F26483A776B"

their_IK="056881C6DEBEF4E85B36F7E6305FEE993F0931B47841B8E455863C9C5FDD11FE1D"
their_SPK="05B09C4CEB5394DA456818F43E562A4A4ECCB0B8F44031AF14A4FB6EE453A55D00"
their_OTK="0528761C9C326955F53589C37BF698F5F937E70D34CE67E2E6C86D6534B167C23B"

ourPrivEK = "9020ba930e38d955df40a413a12a723278d6c5a69fa244a576e15a64fc705a60"
ourEK = "055a413b0885b8d0a559621a90c8ed69816b9ec6b20e4cf66f8e700cf745dddb4e"

chainValue = "4a977707f74d4d802fc509c3fe49d6407ee6a9c4a9168686f742da4cc15a592e"

from base64 import b64decode
from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

ctxt = b64decode("SERDgrF7I0TolKExiiMH67IsQ8Vir6WDr7DUDWc/O74blhiVlJKOA68K9b/1IlMlx1eibdWpX2DV+MkF/sNe9YCPy9qgZmULTiXPcdXt/NDm6maNLn2jbYWTZo5aXMNExc3sfQukcmTtiTfoVuyFL3aQ7Df0ADM6JWVBIm+a3/8VV0B+bNkAFxAEy3fF5PxJ0jbpnVKugWltlU/kXdGD8A==")

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

ourPrivEK = hex2PrivKey(ourPrivEK)
# print(ourEK[2:])
# print("====")
# pk = ourPrivEK.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
# print(hexlify(pk).decode())
ourPrivIK = hex2PrivKey(ourPrivIK)

ourEK = hex2PubKey(ourEK)
their_IK = hex2PubKey(their_IK)
their_SPK = hex2PubKey(their_SPK)
their_OTK = hex2PubKey(their_OTK)

## DH handshake

from controllo import hkdf, SymmRatchet, unpad, hmac_sha256
from Crypto.Cipher import AES


dh1 = ourPrivIK.exchange(their_SPK)
dh2 = ourPrivEK.exchange(their_IK)
dh3 = ourPrivEK.exchange(their_SPK)
dh4 = ourPrivEK.exchange(their_OTK)
sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)

print(f"HANDShAKE: {hexlify(sk).decode()}")

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"WhisperText",
)

sk = kdf.derive(dh1 + dh2 + dh3 + dh4)
print(f"HANDShAKE 22: {hexlify(sk).decode()}")


def dec(self, ctxt: bytes, pubkey: bytes) -> bytes:
    # receive the new public key and use it to perform a DH
    self.dh_ratchet(pubkey)
    key, iv = self.recv_ratchet.next()
    # decrypt the message using the new recv ratchet
    msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ctxt))
    return msg

# set ratchet
root_ratchet = SymmRatchet(sk)
# initialise the sending and recving chains
send_ratchet = SymmRatchet(root_ratchet.next(b"WhisperMessageKeys")[0])
recv_ratchet = SymmRatchet(root_ratchet.next(b"WhisperMessageKeys")[0])

key, iv = send_ratchet.next()
print(f"IV: {hexlify(iv)}")
#iv = bytes.fromhex("ab50a82b28a8d2c587b4c92a63006ed1")
print(len(ctxt))
msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ctxt))
print("Let's see if it decrypted:")
print(msg)

print("blah")

'''
chainKey = hex2PrivKey(chainValue)
#print(chainKey)

msg_key = hmac_sha256(unhexlify(chainValue), b'\x01')
print(msg_key)

chainValue = hmac_sha256(unhexlify(chainValue), b'\x02')
print(chainValue, "----")

msg_key = hmac_sha256(unhexlify(chainValue), b'\x01')
print(msg_key)
chainValue = hmac_sha256(unhexlify(chainValue), b'\x02')
print(chainValue, "----")
'''

Message_kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=80,
    salt=None,
    info=b"WhisperMessageKeys",
)

msg_key = Message_kdf.derive(bytes.fromhex(hmac_sha256(unhexlify(chainValue), b'\x01')))
print(msg_key.hex())

cipher_key = msg_key[0:32]
mac_key =  msg_key[32:64]
iv = msg_key[64:]

chainValue = hmac_sha256(unhexlify(chainValue), b'\x02')
print(chainValue, "----")

#msg_key = "2381f6ba87ea3142636afa0fd888d61ef48d17d7f977fbf43a82a79b6956d937"
msg = unpad(AES.new((cipher_key), AES.MODE_CBC, iv).decrypt(ctxt))
print("Let's see if it decrypted:")
print(msg)
print(msg.hex)

