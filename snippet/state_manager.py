from mitmproxy import ctx, http

from src.mitm_interface import MitmUser
from signal_protocol.address import ProtocolAddress

from typing import Dict
import logging

import json

class StateManager:
    local_cnt = {}

    def load(self, loader):
        loader.add_option(
            name = "request_counts",
            typespec = dict,
            default = {},
            help = "Track number of requests per domain",
        )
        loader.add_option(
            name = "session_data",
            typespec = dict,
            default = {},
            help = "Store session information",
        )

    def request(self, flow: http.HTTPFlow):
        if "v1/registration" or "v2/keys" in flow.request.path:
            domain = flow.request.pretty_host
            counts = ctx.options.request_counts
            #counts: dict = json.loads(counts)
            counts[domain] = counts.get(domain, 0) + 1
            #counts[domain] = MitmUser(protocol_address=ProtocolAddress("aci", "1"), aci_uuid="aci", pni_uuid="1")
            self.local_cnt[domain] = MitmUser(protocol_address=ProtocolAddress("aci", 1), aci_uuid="aci", pni_uuid="1")
            logging.info(f"Request count for {domain}: {counts[domain]}")
            logging.info(f"LOCAL Request count for {domain}: {self.local_cnt[domain]}")

            #ctx.options.request_counts = json.dumps(counts)
            ctx.options.request_counts = counts
            
            # Update request header with count
            flow.request.headers['X-Request-Count'] = str(counts[domain])

            if "iana" in domain:
                raise RuntimeError("No IANA for you!")
            

    def response(self, flow: http.HTTPFlow):
        # if 'Set-Cookie' in flow.response.headers:

        #     #session_data = json.loads(ctx.options.session_data)
        #     session_data = ctx.options.session_data

        #     session_data[flow.request.pretty_host] = flow.response.headers['Set-Cookie']
            
        #     logging.info(f"Session data for {flow.request.pretty_host}: {ctx.options.session_data[flow.request.pretty_host]}")
        #     #ctx.options.session_data = json.dumps(session_data)
        #     ctx.options.session_data = session_data
        
        # logging.info(f"counts response {ctx.options.request_counts}")
        # a = ctx.options.request_counts
        return
    
addons = [
    StateManager()
]