import sqlite3
import json
from pathlib import Path

DB_NAME = "mitm.db"

dbpath = Path.cwd() / DB_NAME
if not Path.exists(dbpath):
    db = sqlite3.connect(DB_NAME)
    cur = db.cursor()
    cur.execute(
        "CREATE TABLE victims(pNumber, aci, pni, aciIdenKey, pniIdenKey, aciSignedPreKey, pniSignedPreKey, aciPreKeys, \
        pniPreKeys,aciFakeIdenKey, pniFakeIdenKey, aciFakeSignedPreKey, pniFakeSignedPreKey, aciFakePrekeys, pniFakePreKeys)"
    )
    res = cur.execute("SELECT name FROM sqlite_master")
    print(res.fetchone())
else:
    print("DB already exists.... skipping")


conn = sqlite3.connect("mitm.db")
cur = conn.cursor()

pNumber = "+412324"
aci = "u32323-ddfw"
pni = "u458483-34343"


cur.execute(
    f"""INSERT INTO victims (pNumber, aci, pni, aciIdenKey, pniIdenKey, aciSignedPreKey, pniSignedPreKey, aciPreKeys, pniPreKeys,aciFakeIdenKey, pniFakeIdenKey, aciFakeSignedPreKey, pniFakeSignedPreKey, aciFakePrekeys, pniFakePreKeys) VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )""",
    (pNumber, aci, pni),
)

identity = "aci"
IdenKey = "abdc"
SignedPreKey = "aa"
PreKeys = json.dumps(["a", "b", "c"])
fake_IdenKey = "abdc"
fake_SignedPreKey = "aa"
fake_PreKeys = json.dumps(["a", "b", "c"])

# cur.execute("CREATE TABLE victims(pNumber, aci, pni, aciIdenKey, pniIdenKey, aciSignedPreKey, pniSignedPreKey, aciPreKeys, \
#    pniPreKeys,aciFakeIdenKey, pniFakeIdenKey, aciFakeSignedPreKey, pniFakeSignedPreKey, aciFakePrekeys, pniFakePreKeys)")
# res = cur.execute("SELECT name FROM sqlite_master")
'''
cur.execute(f"""
    UPDATE victims
    SET {identity}IdenKey = {IdenKey}, {identity}SignedPreKey = {SignedPreKey}, {identity}PreKeys = {PreKeys}, {identity}FakeIdenKey = {fake_IdenKey}, {identity}FakeSignedPreKey = {fake_SignedPreKey}, {identity}FakePreKeys = {fake_PreKeys}
    WHERE {identity}IdenKey ISNULL
    """)
'''


query = f"UPDATE victims SET {identity}IdenKey = ?, {identity}SignedPreKey = ?, {identity}PreKeys = ?, {identity}FakeIdenKey = ?, {identity}FakeSignedPreKey = ?, {identity}FakePreKeys = ? WHERE {identity}IdenKey ISNULL"
print(query)
params = (IdenKey, SignedPreKey, PreKeys, fake_IdenKey, fake_SignedPreKey, fake_PreKeys)
cur.execute(query, params)

conn.commit()
res = cur.execute("select * from victims")
print(res.fetchall())

input()
