# Requirements:
# apt install python3 python3-pip
# pip3 install cryptography==2.8 pycrypto

import base64
from dataclasses import dataclass
from typing import Optional
import hmac, hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES

DISC_BYTES =  b"\xFF"*32


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


def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)


def unpad(msg):
    # remove pkcs7 padding
    return msg[: -msg[-1]]


class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv
    
    def send_ratchet(self, other_pub_DH: bytes):
        # perform a DH ratchet rotation using Bob's public key
        if self.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = self.DHratchet.exchange(other_pub_DH)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.recv_ratchet = SymmRatchet(shared_recv)
            print(f"[{self.__class__.__name__}]\tRecv ratchet seed:", b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(other_pub_DH)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print(f"[{self.__class__.__name__}]\tSend ratchet seed:", b64(shared_send))
    
@dataclass
class KeyBundle:
    IK: X25519PublicKey
    SPK: Optional[X25519PublicKey] = None
    OPK: Optional[X25519PublicKey] = None
    EK: Optional[X25519PublicKey] = None

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
    
    last_person = False
    
    def enc(self, msg: bytes) -> bytes:
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        return cipher

    def dec(self, ctxt: bytes, pubkey: bytes) -> bytes:
        # receive the new public key and use it to perform a DH
        #if self.last_person == False:
        self.dh_ratchet(pubkey)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ctxt))
        return msg

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(self.sk)
        # initialise the sending and recving chains
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
    
    def x3dh(self, other_bundle: KeyBundle):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        if other_bundle.SPK is not None: 
            dh1 = self.IK.exchange(other_bundle.SPK)
            dh2 = self.EK.exchange(other_bundle.IK)
            dh3 = self.EK.exchange(other_bundle.SPK)
            dh4 = self.EK.exchange(other_bundle.OPK)
            self.sk = hkdf(inp = DISC_BYTES + dh1 + dh2 + dh3 + dh4, length=64, info = b"WhisperText")
 #TODO change this
        else:
            dh1 = self.SPK.exchange(other_bundle.IK)
            dh2 = self.IK.exchange(other_bundle.EK)
            dh3 = self.SPK.exchange(other_bundle.EK)
            dh4 = self.OPK.exchange(other_bundle.EK)
            self.sk = hkdf(inp = DISC_BYTES + dh1 + dh2 + dh3 + dh4, length=64, info = b"WhisperText")
            
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        print(f"[{self.__class__.__name__}]\tShared key:", b64(self.sk))


    def recv(self, cipher, bob_public_key):
        msg = self.dec(cipher, bob_public_key)
        print(f"[{self.__class__.__name__}]\tDecrypted message:", msg)
        self.last_person = False #####

    def send(self, other, msg):
        # TODO dovrebbe usare lo stess ratchet fino a quando il recipient risponde mandando un messaggio con nuova key.
        if self.last_person:
            self.dh_ratchet(other.DHratchet.public_key())
            #print(f"[{self.__class__.__name__}]\tSending ciphertext to {other.__class__.__name__}:", b64(cipher))
             ######################

        cipher = self.enc(msg)
        print(f"[{self.__class__.__name__}]\tSending ciphertext to {other.__class__.__name__}:", b64(cipher))
        # send ciphertext and current DH public key
        other.recv(cipher, self.DHratchet.public_key())
        self.last_person = True #####

    def dh_ratchet(self, other_pub_DH):
        # perform a DH ratchet rotation using Bob's public key
        if self.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = self.DHratchet.exchange(other_pub_DH)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.recv_ratchet = SymmRatchet(shared_recv)
            print(f"[{self.__class__.__name__}]\tRecv ratchet seed:", b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(other_pub_DH)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print(f"[{self.__class__.__name__}]\tSend ratchet seed:", b64(shared_send))


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
        self.IK = kwargs.get("IK", X25519PrivateKey.generate())
        self.SPK = kwargs.get("SPK", X25519PrivateKey.generate())
        self.OPK = kwargs.get("OPK", X25519PrivateKey.generate())
        self.DHratchet = kwargs.get("DH", X25519PrivateKey.generate())

if __name__ == "__main__":
    alice, bob = Alice(), Bob()
    alice_bundle,bob_bundle = user2Bundle(alice), user2Bundle(bob)

    # Alice performs an X3DH while Bob is offline, using his uploaded keys
    alice.x3dh(bob_bundle)

    # Bob comes online and performs an X3DH using Alice's public keys (IK, EK)
    bob.x3dh(alice_bundle)
    
    assert(alice.sk==bob.sk)

    # Initialize their symmetric ratchets
    alice.init_ratchets()
    bob.init_ratchets()

    # Print out the matching pairs (debug)
    print("[Alice]\tsend ratchet:", list(map(b64, alice.send_ratchet.next())))
    print("[Bob]\trecv ratchet:", list(map(b64, bob.recv_ratchet.next())))
    print("[Alice]\trecv ratchet:", list(map(b64, alice.recv_ratchet.next())))
    print("[Bob]\tsend ratchet:", list(map(b64, bob.send_ratchet.next())))

    # Initialise Alice's sending ratchet with Bob's public key
    alice.dh_ratchet(bob.DHratchet.public_key())

    # Alice sends Bob a message and her new DH ratchet public key
    alice.send(bob, b"Hello Bob!")

    # Bob uses that information to sync with Alice and send her a message
    #bob.send(alice, b"Hello to you too, Alice!")

    alice.send(bob, b"Do you like Pizza?")

    ## From this point forward the code fucks up.
    ## TODO @andrea - figure it out
    ## Figure it out with multiple messages from one party

    #alice.dh_ratchet(bob.DHratchet.public_key())

    alice.send(bob, b"Let's do crime")
    print(alice.last_person)
    bob.send(alice, b"Si!")
    #bob.dh_ratchet(alice.DHratchet.public_key())

    bob.send(alice, b"HELL YEAH!!!")
    print(alice.last_person)
    print(bob.last_person)
