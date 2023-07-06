#!/usr/bin/env python3.9
"""
Read a mitmproxy dump file.
"""
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException
import pprint
import sys
import mitmproxy

with open(sys.argv[1], "rb") as logfile:
    freader = io.FlowReader(logfile)
    pp = pprint.PrettyPrinter(indent=4)
    try:
        for f in freader.stream():
            # print(f)
            # if isinstance(f, http.HTTPFlow):
            # print(f.request.host)
            if "cdsi" in f.server_conn.sni:
                pp.pprint(f.get_state()["websocket"]["messages"])
            else:
                continue
            print("")
    except FlowReadException as e:
        print(f"Flow file corrupted: {e}")
