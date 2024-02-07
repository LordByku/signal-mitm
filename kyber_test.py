from kyber_protocol import kyber

Kyber = kyber.Kyber1024()
pk, sk = Kyber.keygen()

c, key = Kyber.enc(pk)
_key = Kyber.dec(c, sk)

print(key.hex(), _key.hex(), len(key.hex()), len(_key.hex()), pk.hex(), len(pk), sk.hex())

assert key == _key