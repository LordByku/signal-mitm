from mitmproxy.http import HTTPFlow
#from mitmproxy import ctx
import logging
from xepor import InterceptedAPI, RouteType

# from server_proto import *
from server_proto import addons, HOST_HTTPBIN
api = addons[0]

# print(addons)
# SIGNAL_PRODUCTION_SERVER = "chat.signal.org"
# SIGNAL_STAGING_SERVER = "chat.staging.signal.org"
# HOST_HTTPBIN = SIGNAL_STAGING_SERVER
#api = InterceptedAPI(HOST_HTTPBIN)

@api.route("/v1/registration")
def _v1_registration(flow):
    logging.info("reg")
    # server_proto.v1_registration(flow)
    logging.info(flow.request.content)

# @api.route("/v1/verification") 
def _v1_verification(flow):
    logging.info(flow.request.content)


logging.warning("pulă")
logging.warning(api.find_handler(HOST_HTTPBIN, "/v1/registration")[0])
for idx, (pulă, parser, handler) in enumerate(api.request_routes):
    if pulă != HOST_HTTPBIN:
        continue

    parse_result = parser.parse("/v1/registration")
    if parse_result is not None:
        logging.warning(handler)
        handler = _v1_registration
        api.request_routes[idx] = (pulă, parser, handler)

    parse_result = parser.parse("/v1/verification")
    if parse_result is not None:
        handler = _v1_verification
        api.request_routes[idx] = (pulă, parser, handler)

logging.warning(api.find_handler(HOST_HTTPBIN, "/v1/registration")[0])
logging.warning("chizda mă-tii")
# reg = api.find_handler(HOST_HTTPBIN, "/v1/registration")[0]
# logging.warning(reg)
# reg = _v1_registration
# logging.warning(reg)
# logging.warning(api.find_handler(HOST_HTTPBIN, "/v1/registration")[0])
# api.v1_verification = _v1_verification

addons = [api]