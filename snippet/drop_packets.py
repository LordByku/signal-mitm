from mitmproxy import flow, http
import json


def request(flow: http.HTTPFlow):
    if "/v2/keys/" in flow.request.path:
        data = json.loads(flow.request.content)
        ts = flow.timestamp_created
        identity = flow.request.query.get("identity")
        with open(f"saved/{ts}-{identity}-keys.json", "w") as f:
            f.write(json.dumps(data))

        # todo: if the mitm worked, we'd generate our own keys here to the server
        # and persist alices in sth better than a file (i.e LEARN SQLlite dummy 😇)
