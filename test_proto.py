from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
from base64 import b64decode

def remove_pad(padded_msg: str):
    padded_msg = padded_msg.rstrip("0")
    #print(padded_msg)
    try:
        if padded_msg[-1] == '8':
            return padded_msg[:-1]
    except:
        return ValueError("Wrong padding" + padded_msg.hex())
         

from builtins import bytes

prekeySignalMessage = PreKeySignalMessage()

pksm_hex = "08c3fcad0612210592022289580f48aaa02cc6215c92d897880f1afcca6f5913036a6ae0d421ad591a2105fceb87526f2c5e039a8c222f60bdcc8ae18027256ce5914f38f646b1c1b0fa7622d301330a210525dfe93c41350b035843d65546bf09623a42391e301872c248843435a20e812b1001180022a00100f5bd5ebcd946a740e202301ad2623e83bb85c37dc2d95620e49c8ce4136fdf562532f9cc365506f0a6e9901f89117d0b6d7ab7cc085b156eb57f31e1c04e15597b0315bb10faf59dd8d911865af5e409f9dfe8f19693284d208e22cc24008b01d2c4377c3b4f1804e34ee875d895c6fa96e9bd8857b8d667171037a6697f87c54e705e7fba5158b67f329d9f0ebb84e07518077acaf4fb7a0be8d277204c9eefeefa28d1f62207288b2f30888ee505"

prekeySignalMessage.ParseFromString(bytes.fromhex(pksm_hex))


SignalMessage = SignalMessage()


SignalMessage.ParseFromString(bytes(prekeySignalMessage.message[1:-8]))

print(SignalMessage)

message = "Mwjtk6wCEiEFUwTOc5K/xCxBq0EgW80qul3qPjzx37dU0Wa7Ag5TCVAaIQX864dSbyxeA5qMIi9gvcyK4YAnJWzlkU849kaxwbD6diLTATMKIQWSHZ4mOBO07RKdfqT/YGGA6jReEXuGKd0BMgOyaVXeDxAAGAAioAFAUuHIfmjsi/pktPDXTtWb9Dh442JFNQ5S9uNjV30J+RIv/j0EL8VXC1v8YMJKrXP/94p1g7VHNCSBygejAKvIzgBpUhLoqJa+4R/6QNU6Cs0fCvdLBYQsqZwFRK8LWdcAjLH92ilzsyNl2tFHLO2Vfa+fqj1/Akc3snP05BIisahkUFMmvrU1de2kS0f+rxsvrbLspONWxzTQpuW8/sYy+fJj5z20ONwoiy8wpbnLBg=="



### decode64 it and strip message version and ciphertext type(first two bytes ) and last 8 bytes
message = b64decode(message)

mess_type = message[:1]
print(f"message type: {mess_type}")

message = message[1:]


'''
envelope = Content()
envelope.ParseFromString(message)
print(f"HELP {envelope}")
'''
##### check the message type and proto decode it accordingly -- for this example we avoid the check of the type
prekeySignalMessage.ParseFromString(message)

message = prekeySignalMessage.message
mess_type = message[:1]
mac = message[len(message) - 8:]
print(mess_type.hex(), mac.hex())
message = message[1:-8]

SignalMessage.ParseFromString(message)

print(SignalMessage)


plaintext = "0a6b0a40576f6d656e2061726520796f7520646f696e6720746f646179204920616d2068617264657220746f2067657420707265676e616e742077697468206120626f7932208dc269f19ba50711fba549653b59fc4e36bfd1b1629ea043e452ebc44e2b7c5138aee6dda694318000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

plaintext = remove_pad(plaintext)
print(bytes.fromhex(plaintext))
ptxt = Content()

ptxt.ParseFromString(bytes.fromhex(plaintext))

print(ptxt.dataMessage)

print(ptxt.SerializeToString())
