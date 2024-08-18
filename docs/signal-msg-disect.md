# The Anatomy of a Signal Message

---
tl;dr: The process of encoding a raw text message from A to B (`raw_msg` is bytes ofc)
```
raw_msg --> Content (protobuf) --> padded\_content (bytes) --> ctxt (protocol.CiphertextMessage) --> outgoing_msg (Base64.encode) --> envelope (JSON) -> WebSocketMsg (protobuf)
```

---

> Simplifying assumptions: 
> - new conversation (ratchets at 0, no pre_key bundles)
> - profile is known however (e.g. via CDSi or username) -- meaning we have an identifier, NOT necessarily a profile key though
> - first message is an actual message (typing indicators /  read receipts disabled)
> - default receiver (sealed sender is NOT allowed for new message requests)
> - one receiving device

Each of these could be handled easily, but it's ~~a chore~~ an exercise to the reader.

Premise:
A sends the message "Hi" to B.

1. A creates a `Content` object (c.f. `SignalService.proto`) describing the data it wants to send. (In our case it will always be a `DataMesage` with body="Hi" ). In pseudo-code `content := CreateContentProtobuf(body="Hi", timestamp=now(), profileKey=ourProfileKey)`. The PK is just for convenience so B can decrypt A's Attributes (display name, pic, etc) 

2. A retrieves B's bundle, and processes it. This will create an associated session in their `SignalStore`.

3. Then content must be prepared for encryption. TO do so it is serialized to bytes and padded using the `PushTransportDetails` custom padding (+1 -1 byte fun). `padded_content := PushTransportDetails.get_padded_message_body(content)`

4. The content is encrypted using a session_cipher: `ctxt := session\_cipher.encrypt(store, B.address, padded\_content)` . This will produce a `CiphertextMessage` (In our case a `PreKeySignalMessage`, as we can tell from the type.). All `CiphertextMessage` types wrap an inner `SignalMessage` that contains the ciphertext and ratcheting state.

5. The CiphertextMessage is then serialized and encoded to base64 (with padding!): `outgoing_msg := Base64.encodeWitPadding(ctxt)`. 

6. The base64 message is wrapped into an OutgoingPushMessage (type is defined in `Envelope.kt` and it is **NOT** guaranteed to match the `messageType` -- look at `WhipserType` being 2 in signal proto and 1 on Envelope). OutgoingPushMessage can be batched together on the sending/receiving side. (todo: not sure if the server does any batching for retrieving messages) The JSON structure of the `Envelope` is as follows:

```json
{
   "destination":"((ACI/PNI identifier))",
   "messages":[
      {
         "content":"((msg from step 5.))",
         "destinationDeviceId":1,
         "destinationRegistrationId": "((obtained from processing the pre_key bundle))",
         "type": "((ENVELOPE_TYPE, see Envelope.kt))"
      }
   ],
   "online":true,
   "timestamp":1723727607335,
   "urgent":true
}
```

7. The `OutgoingPushMessageList` is turned into a `WebSocketRequest` message and sent on the wire (PUT to `/v1/messages/{destination}`)


## Nota bene

1. Serialized message formats:
   - `CiphertextMessage/PrekeySignalMessage`: `type` (1 byte) + protobuf serialized `message` 
   - `SignalMessage`: `type` (1 byte) + protobuf serialized `message` + `mac_tag` (8 bytes)
2. Whenever possible/sensible try to rely on abstractions given by `signal-protocol.py`.
   - It is easier to use:
```python
from signal_protocol.protocol import PreKeySignalMessage
raw_bytes = b""
pksm = PreKeySignalMessage.try_from(raw_bytes)
``` 

than using

```python
from wire_pb2 import PreKeySignalMessage as PreKeySignalMessageProto
raw_bytes = b""
pksm = PreKeySignalMessageProto()
pksm.ParseFromString(raw_bytes[1:])
```