from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
from proto_python.sealed_sender_pb2 import *
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

prekeySignalMessage = UnidentifiedSenderMessage()

pksm_hex = "0a2105be6caa20120624f125bf8b8b976f5f8ecc4054c24cd47e9acffbcd8f93fc7a31122bcf98c6e3678395e7ddbd92729e648d95c24ce6a7c05ea27a0f0688044c9d959c7dc2749676fff1845bce961af90381e54fb3dd127012e220b674a65257163d23ce418a6bb70209ac7d13f3d68de8abe85959cc55dfa24c97373a42aca5af3685592e89e807998771b9e046def8ad1a8cdeb355ba10b9e22c3a124ec279fd91dc5adbd760c4bb685810933cb7ae4e694c33b226e359b6bc34e1ddee020674c7169e4fa53ac972199296a2293f50249861f37ca90f0ef9b6d17e464f39bfde16f1c906a8f220db4d3d1f98d3b67fd2bd3620bdbfd8fcee2e806a2c1451a0562e55e6ca03964132593196ef39ad09ea360d3bb28dab8e91fcf83cc7282a4569453fec9363cca85ee85e180013fd06314d4e320967567538cd95434c7dce4b1946f889cabe91709cbb5e47bb03f5d44b4abcb3387693edaab82293d33e9c0e1d0512552564e0deb0770657575f7ed6a5b7bfd8afe568ec45aa937882cc55f7a8c528628320ec57b341b5a367731bdd98785805de2b8374775c0cce52b5143b5033d3e30d497414ef873dc9343aa8c7dbd4360b3b68f463fea3637422f234b5069de0f25c23b97a059aa36a51fde9ecb8adb331cbfe14bc9c80d163118f493d4bb1518ca037610c5f9a9ebdf6dc4132bfa29ea4c8a251e5fd99b9c6c6f17ff88ce3f88881baaa1e05d02bc59b28c8737f9603cd337ae1142af7d0b3f24c0d1a55363b95df9579d21dd027c5d1d8fb81ef6ec5d64b8c2ac6d639c368d3dfe7134d0d48765e8f516b09"

prekeySignalMessage.ParseFromString(bytes.fromhex(pksm_hex))

print(prekeySignalMessage)

exit()
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
