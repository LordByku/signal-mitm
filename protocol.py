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

DISCONTINUITY_BYTES =  b"\xFF"*32

############################ Helper Functions ############################
def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode("utf-8").strip()

def hmac_sha256(key: bytes, msg: bytes):
    result = hmac.new(key, msg, digestmod=hashlib.sha256).hexdigest()
    return result

