from mitmproxy import http
import logging

def request(flow: http.HTTPFlow) -> None:
    if "/v1/registration" in flow.request.path:
        logging.info(f"REQUEST HERE {flow}")

def response(flow: http.HTTPFlow):
    if "/v1/registration" in flow.request.path:

        logging.info(f"RESPONSE HERE {flow}")

        logging.info(f"registering {flow.request.text}")