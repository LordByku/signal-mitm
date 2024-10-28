# Serialization module(s)

The serialization module provides a way to serialize and deserialize data. We analyze two aspects:
- ## Input interface: 
    - How data is provided to the CryptoMall module. Originally, the data coming from the client was firstly deserialized in ```implementation.py``` and handled by ```MitmUSer``` class that communicated directly with ```signal-protocol.py```. 

- ## Output interface: 
    - How data is provided to the client/server. The data is serialized in ```implementation.py``` and sent to the client/server (outgoing message from mitmproxy to the wire).


In general, data that we receive from the external world (client/server) consists in a "matrioska" of different serialization layers. The layers from the outer to the inner are:

- The first layer depending on the nature of the data, can be:
    - WebSocket layer, where the data is protobuf serialized in bytes. The schema followed is defined in ```WebSocketResourceProto.```.
- The second layer is the HTTP layer, where the data is serialized in JSON format.
- The third layer is the data itself, which can be ```string```, ```int```, ```bytes```. As a general rule:
    - cryptographic keys are serialized in ```base64``` strings of the bytes.
    - ids are serialized in ```int```.
    - messages are serialized in protobuf bytes. The schemas are defined in ```wire.proto``` and ```SignalService.proto```.

- The fourth layer is the Internal Serialization layer which is handled by ```libsignal``` library (in our case, ```Crypto Mall```). Relevant to say that this layer is not visible to the external world and we do not control it directly.

## High-level design
![](images/Serialisation%20Module%20(high%20level)%20.jpg)

## Protobuf link 

### ```v1/registration``` - REQUEST:
- (aci)registrationId: ```int```
- pniRegistrationId: ```int```
- unidentifiedAccesskey: ```base64```
- Identitykey: ```base64```
- PqLastResortPreKey: ```base64```
    - keyId: ```int```
    - publicKey: ```base64```
    - signature: ```base64```
- SignedPreKey: ```base64```
    - keyId: ```int```
    - publicKey: ```base64```
    - signature: ```base64``` 

### ```v1/registration``` - RESPONSE:
- uuid (aciId): ```string```
- pni: ```string```
- number: ```string```


### ```PUT v2/keys``` - REQUEST:
- pqPreKeys: 100 keys
    - keyId: ```int```
    - publicKey: ```base64```
    - signature: ```base64```
- PreKeys: 100 keys
    - keyId: ```int```
    - publicKey: ```base64```

### ```v2/keys/{uuid}``` - RESPONSE:
- deviceId: ```int```
- pqPreKey:
    - keyId: ```int```
    - publicKey: ```base64```
    - signature: ```base64```
- PreKey:
    - keyId: ```int```
    - publicKey: ```base64```

- registrationId: ```int```

- signedPreKey:
    - keyId: ```int```
    - publicKey: ```base64```
    - signature: ```base64```

- identityKey: ```base64```

### ```v1/messages/{uuid}``` - REQUEST:
- destination: ```string```
- message: 
    - type: ```int```
    - content: ```base64``` - this is the serialized protobuf message

- deserialized content:
    - if type == 3:
        - protobuf: PreKeySignalMessage 
            ```protobuf
            message PreKeySignalMessage {
            optional uint32 registration_id   = 5;
            optional uint32 pre_key_id        = 1;
            optional uint32 signed_pre_key_id = 6;
            optional uint32 kyber_pre_key_id  = 7;
            optional bytes  kyber_ciphertext  = 8;
            optional bytes  base_key          = 2;
            optional bytes  identity_key      = 3;
            optional bytes  message           = 4; // SignalMessage
            }
            ```
        if type == 6:

        - protobuf: SignalMessage
            ```protobuf
            message UnidentifiedSenderMessage {

                // There are additional fields in the original protobuf message

                optional bytes ephemeralPublic  = 1;
                optional bytes encryptedStatic  = 2;
                optional bytes encryptedMessage = 3;
            }
            ```

### ```api/v1/messages/{uuid}``` - RESPONSE:
- deserialize the protobuf message and return the content to the client
- outer protobuf:
```protobuf
                message Envelope {
                    enum Type {
                    UNKNOWN             = 0;
                    CIPHERTEXT          = 1;
                    KEY_EXCHANGE        = 2;
                    PREKEY_BUNDLE       = 3;
                    RECEIPT             = 5;
                    UNIDENTIFIED_SENDER = 6;
                    reserved 7; // SENDERKEY_MESSAGE
                    PLAINTEXT_CONTENT   = 8;
                    }

                    optional Type   type                 = 1;
                    reserved      /*sourceE164*/           2;
                    optional string sourceServiceId      = 11;
                    optional uint32 sourceDevice         = 7;
                    optional string destinationServiceId = 13;
                    reserved      /*relay*/                3;
                    optional uint64 timestamp            = 5;
                    reserved      /*legacyMessage*/        6;
                    optional bytes  content              = 8; // Contains an encrypted Content
                    optional string serverGuid           = 9;
                    optional uint64 serverTimestamp      = 10;
                    optional bool   urgent               = 14 [default = true];
                    reserved      /*updatedPni*/           15; // Not used presently, may be used in the future
                    optional bool   story                = 16;
                    optional bytes  reportingToken       = 17;
                    reserved                               18;  // internal server use
                    // NEXT ID: 19
                }
```
- inner protocol:
    - PreKeySignalMessage
    - SignalMessage