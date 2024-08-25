import base64

from Crypto.Util.RFC1751 import binary
from Crypto.Util.py3compat import tobytes
from mitmproxy.tools.console.keymap import KeyBindingError

import utils
from mitm_interface import MitmUser
from signal_protocol.address import ProtocolAddress, DeviceId

# from signal_protocol import ession_cipher

content = "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"
content = base64.b64decode(content)


destination_id = 1
destination_reg = 539
msg_type = 3 # good

from signal_protocol.identity_key import IdentityKeyPair, IdentityKey
from signal_protocol.curve import PrivateKey, KeyPair

ik = IdentityKeyPair(
        IdentityKey.from_base64("Bedj0IADMGdj+RE2EU/xQXowidmcNdtUIykWvseZZhpn".encode()),
        PrivateKey.from_base64("0AglLVkjIWC+QHz41ai2xDfhv0iVjbN1jkzoKA2J73E=".encode())
)

from signal_protocol import kem

# [{"keyId":10004538,"publicKey":"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","signature":"ffJqYf3RT653owvCVTuoMr8RbInjIp08D3qY8FHYfFuiocXPW9txJUcSmkM7XRCPZ2OwiI9Th+9CX5izBWqzDw","privateKey":"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"}]
kp : kem.KeyPair = kem.KeyPair.from_public_and_private(
    base64.b64decode("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"),
    base64.b64decode("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")
)

args = {
    # {"publicKey":"Bedj0IADMGdj+RE2EU/xQXowidmcNdtUIykWvseZZhpn","privateKey":"0AglLVkjIWC+QHz41ai2xDfhv0iVjbN1jkzoKA2J73E="}
    "identity_key": ik,
    # {"keyId":6026970,"publicKey":"BYNvswv2Lxo5tHCR3tg7X8qeOpv8hGVNC2/3BwH/LMo3","signature":"7Ug2x9ZSSOGrYGeH2VxmVCmiV8nkc6gFVKPehqEGv+HoKRd+Qtn+O0mNUDjaviLd4wtO5p3cJIAG/6NOs5dVCw","privateKey":"uN8x8dV6VQm32rO2QKVe3ZvrYSk68ht6ngK1hw8bJVg="}
    "signed_pre_key": KeyPair.from_public_and_private(
        base64.b64decode("BYNvswv2Lxo5tHCR3tg7X8qeOpv8hGVNC2/3BwH/LMo3"),
        base64.b64decode("uN8x8dV6VQm32rO2QKVe3ZvrYSk68ht6ngK1hw8bJVg=")
    ),
    "signed_pre_key_id":6026970,
    # [{"keyId":10588852,"publicKey":"BaFExFNFEZyy7S5N8+rkl5H/9Fr0vQ/HxOVW2tRYmWNG","privateKey":"CJWkUylAhEdq8udcBvrKci/aB8J/r/nclocY83oIYFg="}]
    "pre_key_id":10588852,
    "pre_key": KeyPair.from_public_and_private(
        base64.b64decode("BaFExFNFEZyy7S5N8+rkl5H/9Fr0vQ/HxOVW2tRYmWNG"),
        base64.b64decode("CJWkUylAhEdq8udcBvrKci/aB8J/r/nclocY83oIYFg=")
    ),
    "kyber_pre_key_id":10004538,
    "kyber_record": utils.make_kyber_record(10004538, 1724592884969, kp,
                    base64.b64decode("ffJqYf3RT653owvCVTuoMr8RbInjIp08D3qY8FHYfFuiocXPW9txJUcSmkM7XRCPZ2OwiI9Th+9CX5izBWqzDw==")
    )
}


# todo: maybe strip
fakeUser = MitmUser(
    address=ProtocolAddress("PNI:35762c93-ab19-4fdc-af8d-f21e6d1b52ef", destination_id),
    RID=destination_reg,
    **args
)

print(fakeUser.kyber_pre_key_id)



# print(kp)

kyber_crap = "081bfbecf8ff86df64479c6f28cb276933b91afedb912d94339df1ba83ba0ada39de031d0c846f06c81731ce528684649186fe022fd760a6a7931fd2387dab4ba3c9d1a5d52d47f29b8e532b89428b3b106c792075d7a3951310d27a2dda88bb5d3fe5b9b5bd0b43913ac4f93d8b12cce29c351b449541f57127f1050f0a333a2b5a4aa5505531f5b33808babd0dd8089221478e6fc933f71c2d1268b5612dbf41171de9a5703688314efd00d9558b900ed8038f8e71d8cc2ea5e295a1ae68ed89585eba274d51245395efcd8e9d40a6b475215e24a44c1c73abbe4fa8440337e048f785b89bdecb01ddf543978c39c97f1cc9d8edddac24cf7f32dfdecd0c7ed5077480cd4f2308c710c29f463edd3ee35529e61dc435969ac4e806c96a2dd699137009f252fd899f10bc473316f573ad6b43f1f2b666f3f655feffd6ca8476798d338eda392c2c274d76f3a389ad1e7b2e94a3af899b436142578a5301d24f4542e4d72a81ac46598b40145016dd772b02def96eccf48a9ea01fec0a4080f07d4cdfea6980e94076aba90c2c630fe8b0f41b7634abe56e2edc4f57e94c5e300de0efeb32f524e3dbd533f3f345800118c325e70932dc7b1ee63322ab6581b6f0a3d9324d7d5810de5854a39b6fc2a7414f910972a68b3111bcd854d4c9edca29e6b073c51d7c6f158ea592b77fc8de562544bec8b73b98eeeb8afbaf4fa760e02cd891dc752fb811cb9b065c38366a67aeb6dca7568db476603500e158529489bc1c0dccbd5541fb4903d485c2bc24424f795aefb46fe420dbacc5d2da40b50edd5df175d2c076fe32c2166080f0acd388b284d18f65008cba4210d33fb859b07711c320b865359b613da4e35f3417110d38a00a32e3880e326ee622cef92d74002cb37e17612be4037be6658081d50cb268037911b656256eed8068d91c50dc7eb3db696a857917a3f96e44e51ef6051a0627f745ba92236f6cc565293a66df56deee2d305616484984d2f48db1d29a065a5b2a6a48b53afd5877c426b0137fdc157560e0493caadfe65e239a00b7b2bee2c6f19acc73f4a7755ef5440e22311983688bb7db41ba021648f72c54d09251bd72f19817abb95e3f3d397e91d50f66103b8cbe43307517d96f65f42bea9d83ab51b540fa66b75aaaeb4fbe775551a0d0861511f78c5d8bf3c0da67f293de03654a572706aa0369c6d66c07a6281703c6c7fc8a7cef915694e42326392ac930ae47e140bb51c8c19dbd0aac8b5800d1c6e8766d9923a53d843a41b1891467e9d60dca79d0f282ec4034f113dda6fd90bc24fa9c4cf25fcb0bd71402dcb210cd1d0348b8e597aa7cd8d6840c207c0d42157c91962cccde85f568aab14e9e6982500d098d3e7f45e8db7380e02b458b3d1fc8bed2fcb7c975666e07bea953ea219402159408c982afc2dd40d3c0c016f6748d1480b31b843318d2ffd42be7b1bc0ed5a6a4e124f12c23be7d335578170115371091e7fd6de90fb0c966f38efeb7c3868c36ee06ae1b69a27b80f3c3b6b2809c3a5df4932b89e5c192b69e51bed7685f721c202e94b7339f107c81d526a87ec0e30478542f8dbe11d089ba4250b2a5b3cc5883ad4815229ea2fc45e00760ea6e946992a50face7281c1a992ce8c2faef2949d23ebc2a99e28cba0ee9c0537127a6bca96ac7811b5bf9e171cfc6c331be2fe328c1dc10423e3d146fb0541acda332561ed766ca7bf288ebb8cd8857c4dbff562aa7d29b99ce1c8725be373a85936c1447704133da1de87d5e339abf399e8baa9914c88cef399ed3316496d55608cf9d43807bcbf8ad49855bf95f52699496dcc7a6cc65a95d41e71529683e074268811f5318642c9f6170292316b4ecfc9a7626b78140f8801ace5d4ee82df60dbca5d5d9141c8cee19d35ff7250e9356591ce60be2f98dacd6192416509e9ecbd0bce9e8eddd5608026bf132ba94d56ab089e14b01f0ec2bd8647b4b7b94b0c274a5ab8ce96218f67fad33d02c89c7b292d4effb263409a625ae0e2274a3cf4dbf66938f87d2f446ba56a003f7305c2eb1774489e09e2ac90de6226b8fd9840f1eea34e9887af9de9e80014ce7b7640f434f132c894a207df0d3bcd720ec37f771b0794b81d27e64eb5f4b95a7a9d86dea705746497ef1cb1c07182eb7c8263ff5b95519f9392003ecf1f456001abf90497f099852882a35e1dbb83c02"
kyber_crap = bytes.fromhex(kyber_crap)

ss_for_recipient = kp.decapsulate(kyber_crap)
print(ss_for_recipient.hex())

from signal_protocol.state import KyberPreKeyRecord

from signal_protocol.state import PreKeyId, KyberPreKeyId, SignedPreKeyId, SignedPreKeyRecord, PreKeyBundle, PreKeyRecord, KyberPreKeyRecord

# key_id = 10004538
sig = ik.private_key().calculate_signature(kp.get_public().serialize())#.hex()
# attempt = "08" + key_id.to_bytes(4).hex() + bytes(5).hex() + kp.get_public().serialize().hex()+kp.get_private().serialize().hex() + sig
# attempt = bytes.fromhex(attempt)
# k_rec = KyberPreKeyRecord.deserialize(attempt)

temp_kyber = KyberPreKeyRecord.generate(
    kem.KeyType(0),
    KyberPreKeyId(10004538),
    ik.private_key()
)

target = temp_kyber.serialize().hex()


# ours = sss.SerializeToString()
#
# pd = KyberPreKeyRecord.deserialize(ours)
# print(type(pd.)

# print(len(ours) == len(target))
# print(ours)

fakeUser.decrypt(
    ProtocolAddress("PNI:c2512faf-36c2-4253-abdb-573e8e2bf477", 1),
    content
)