import sqlite3


def encrypt(msg):
    # handle websocket messages before
    # endpoint: /v1/messages/{aci/uuid}
    conn = sqlite3.connect("mitm.db")
    cur = conn.cursor()

    # identify target

    query = f"SELECT * from victims WHERE aci LIKE ..."

    output = cur.execute(query)
    print(output.fetchone())
