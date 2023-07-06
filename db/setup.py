# handle to check if

# - db exists

# - if not -> run all the sql files in order

# - if it exists -> check version. run only nums after

from pathlib import Path
import sqlite3

DB_NAME = "mitm.db"


def setup_db():
    dbpath = Path.cwd() / DB_NAME
    if not Path.exists(dbpath):
        db = sqlite3.connect(DB_NAME)
        cur = db.cursor()
        cur.execute(
            "CREATE TABLE victims(pNumber, aci, pni, aciIdenKey, pniIdenKey, aciSignedPreKey, pniSignedPreKey, aciPreKeys, \
            pniPreKeys,aciFakeIdenKey, pniFakeIdenKey, aciFakeSignedPreKey, pniFakeSignedPreKey, aciFakePrekeys, pniFakePreKeys, \
                PRIMARY KEY (pNumber, aci, pni));"
        )
        res = cur.execute("SELECT name FROM sqlite_master")

        cur.execute(
            "CREATE TABLE end2end(v_aci, recv_aci, deviceId,recv_IdenKey, recv_SignedPreKey, \
            recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey)"
        )
        print(res.fetchone())
    else:
        print("DB already exists.... skipping")
