import base64
import utils
from signal_protocol.address import ProtocolAddress
from signal_protocol.state import (
    PreKeyId,
    KyberPreKeyId,
    SignedPreKeyId,
    SignedPreKeyRecord,
    PreKeyRecord,
    KyberPreKeyRecord,
)
from signal_protocol.storage import InMemSignalProtocolStore
from signal_protocol.identity_key import IdentityKeyPair, IdentityKey
from signal_protocol.curve import PrivateKey, KeyPair
from signal_protocol import kem
from signal_protocol import session_cipher
from signal_protocol.protocol import PreKeySignalMessage
from protos.gen.SignalService_pb2 import Content

content = "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"
content = base64.b64decode(content)


destination_id = 1
destination_reg = 539
msg_type = 3  # good

ik = IdentityKeyPair(
    IdentityKey.from_base64("Bedj0IADMGdj+RE2EU/xQXowidmcNdtUIykWvseZZhpn".encode()),
    PrivateKey.from_base64("0AglLVkjIWC+QHz41ai2xDfhv0iVjbN1jkzoKA2J73E=".encode()),
)


# [{"keyId":10004538,"publicKey":"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","signature":"ffJqYf3RT653owvCVTuoMr8RbInjIp08D3qY8FHYfFuiocXPW9txJUcSmkM7XRCPZ2OwiI9Th+9CX5izBWqzDw","privateKey":"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"}]
kp: kem.KeyPair = kem.KeyPair.from_public_and_private(
    base64.b64decode(
        "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"
    ),
    base64.b64decode(
        "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"
    ),
)

args = {
    # {"publicKey":"Bedj0IADMGdj+RE2EU/xQXowidmcNdtUIykWvseZZhpn","privateKey":"0AglLVkjIWC+QHz41ai2xDfhv0iVjbN1jkzoKA2J73E="}
    "identity_key": ik,
    # {"keyId":6026970,"publicKey":"BYNvswv2Lxo5tHCR3tg7X8qeOpv8hGVNC2/3BwH/LMo3","signature":"7Ug2x9ZSSOGrYGeH2VxmVCmiV8nkc6gFVKPehqEGv+HoKRd+Qtn+O0mNUDjaviLd4wtO5p3cJIAG/6NOs5dVCw","privateKey":"uN8x8dV6VQm32rO2QKVe3ZvrYSk68ht6ngK1hw8bJVg="}
    "signed_pre_key": KeyPair.from_public_and_private(
        base64.b64decode("BYNvswv2Lxo5tHCR3tg7X8qeOpv8hGVNC2/3BwH/LMo3"),
        base64.b64decode("uN8x8dV6VQm32rO2QKVe3ZvrYSk68ht6ngK1hw8bJVg="),
    ),
    "signed_pre_key_id": 6026970,
    # [{"keyId":10588852,"publicKey":"BaFExFNFEZyy7S5N8+rkl5H/9Fr0vQ/HxOVW2tRYmWNG","privateKey":"CJWkUylAhEdq8udcBvrKci/aB8J/r/nclocY83oIYFg="}]
    "pre_key_id": 10588852,
    "pre_key": KeyPair.from_public_and_private(
        base64.b64decode("BaFExFNFEZyy7S5N8+rkl5H/9Fr0vQ/HxOVW2tRYmWNG"),
        base64.b64decode("CJWkUylAhEdq8udcBvrKci/aB8J/r/nclocY83oIYFg="),
    ),
    "kyber_pre_key_id": 10004538,
    "kyber_record": utils.make_kyber_record(
        10004538,
        1724592884969,
        kp,
        base64.b64decode(
            "ffJqYf3RT653owvCVTuoMr8RbInjIp08D3qY8FHYfFuiocXPW9txJUcSmkM7XRCPZ2OwiI9Th+9CX5izBWqzDw=="
        ),
    ),
}

sig = ik.private_key().calculate_signature(kp.get_public().serialize())  # .hex()

temp_kyber = KyberPreKeyRecord.generate(
    kem.KeyType(0), KyberPreKeyId(10004538), ik.private_key()
)

target = temp_kyber.serialize().hex()

my_addr = (ProtocolAddress("PNI:35762c93-ab19-4fdc-af8d-f21e6d1b52ef", destination_id),)

store = InMemSignalProtocolStore(ik, destination_reg)
print(store)

spk_id = SignedPreKeyId(args["signed_pre_key_id"])
spkr = SignedPreKeyRecord(
    spk_id,
    1724592884969,
    args["signed_pre_key"],
    base64.b64decode(
        "7Ug2x9ZSSOGrYGeH2VxmVCmiV8nkc6gFVKPehqEGv+HoKRd+Qtn+O0mNUDjaviLd4wtO5p3cJIAG/6NOs5dVCw=="
    ),
)
store.save_signed_pre_key(spk_id, spkr)

pk_id = PreKeyId(args["pre_key_id"])
pkr = PreKeyRecord(
    pk_id,
    args["pre_key"],
)

store.save_pre_key(pk_id, pkr)

kyber_id = KyberPreKeyId(args["kyber_pre_key_id"])
store.save_kyber_pre_key(kyber_id, args["kyber_record"])

sender_addr = ProtocolAddress("bob", 1)

ctxt_data = PreKeySignalMessage.try_from(content)
ptxt = session_cipher.message_decrypt(store, sender_addr, ctxt_data)
print(ptxt)

c = Content()

ptxt = utils.PushTransportDetails().get_stripped_padding_message_body(ptxt)
c.ParseFromString(ptxt)
print(c)
