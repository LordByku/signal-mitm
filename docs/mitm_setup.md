---
title: Setup Docs
language_tabs:
  - curl: Curl
  - python: Python
language_clients:
  - curl: ""
  - python: ""
toc_footers: []
includes: []
search: false
highlight_theme: darkula
headingLevel: 2

---

<h1 id="setup_docs">Setup docs</h1>


## Certificate installation
- cd /home/snake/StudioProjects/Signal-Android/app/src/main/res/raw

-  keytool -list -v -keystore whisper.store     -storepass "whisper" -storetype bks -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath ~/Downloads/bcprov-jdk18on-173.jar 
```

1. install the signal root of trust on dev machine

2 test if it works

3. get a MiTM cert from whatever proxy we use (mitmproxy)

4. bundle it into a nice keystore (pass=whisper) -- SHOULD BE a DROP_IN replacement

5. Recompile the app with the new whisper.store
``` 

> Here we set where the redirections that the traffic from the wifi interface (client/phone) such that the traffic reaches internet throught the ethernet interface. 

```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.send_redirects=0

iptables -t nat -A PREROUTING -i wlp0s20f3 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i wlp0s20f3 -p tcp --dport 443 -j REDIRECT --to-port 8080
ip6tables -t nat -A PREROUTING -i wlp0s20f3 -p tcp --dport 80 -j REDIRECT --to-port 8080
ip6tables -t nat -A PREROUTING -i wlp0s20f3 -p tcp --dport 443 -j REDIRECT --to-port 8080

sudo create_ap --freq-band 2.4  wlp0s20f3 wlx482254431544 DummyHotspot 1234567890 


iptables -t nat -A PREROUTING -i ap0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i ap0 -p tcp --dport 443 -j REDIRECT --to-port 8080
ip6tables -t nat -A PREROUTING -i ap0 -p tcp --dport 80 -j REDIRECT --to-port 8080
ip6tables -t nat -A PREROUTING -i ap0 -p tcp --dport 443 -j REDIRECT --to-port 8080


```

sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv4.conf.all.send_redirects=1

> Install the certificate on the signal_messenger_ca (certificate) on the dev machine.

```bash
sudo mkdir /usr/share/ca-certificates/extra 
sudo cp ~/Documents/ETH/thesis/mitm/signal_messenger_ca.cer /usr/share/ca-certificates/extra/
sudo update-ca-certificates
```

## Checks

```bash
ls /usr/share/ca-certificates/extra/ -lha 
curl https://updates2.signal.org/ -vv
```

## mitmproxy command

```bash
mitmproxy --mode transparent --showhost --ssl-insecure --ignore-hosts ".*google\w*\.com"
```

Flag explanation:
- **transparent**: We do not have control over the client's request, in general behaviours, so we need a transparent proxy, where traffic is directed into a proxy at the network layer, without any client configuration required.
- **--ssl-insecure**: Do not verify upstream server SSL/TLS certificates, since the certificate is pinned.
- **-ignore-hosts**: We ignore traffic with the ".*google\w*\.com" in order to not interfere traffic which is relevant for the registration (Firebase Cloud messaging). This avoids failing the push challenge in the registration process since the certificate from mitmproxy fails because missing validation of certificate. (Google hates me because I am shady and cheeky).

## ACI
An ACI is an "Account Identity". They're just UUIDs, but given multiple different things could be UUIDs, this wrapper exists to give us type safety around
 * this *specific type* of UUID.

## key generation

-ECC 25519-darlek modified without cofactor. Tricky, use the one from the signal implementation (Rust Library, usable nodejs, javascript)


## Sealed Sender

> Target

Allow [Sealed Sender](https://signal.org/blog/sealed-sender/) feature

>Setup

Target user has set to off the "Allow from anyone":

> **_Allow from anyone:_**
Enable sealed sender for incoming messages from non-contacts and people with whom you have not shared your profile


Attacker (MitM) is **active** and send a POST request to the server at this endpoint [v1/accounts/attributes/](https://chat.staging.signal.org/v1/accounts/attributes/) by setting the property "unrestrictedUnidentifiedAccess" to true, so basically allowing the feature.

When the unkwown sealed sender user sents a message to the target, by rule this message should be blocked since the target user set the feature to off.


> Explanation

The server receives the POST req from the attacker, assuming it is the client, and change the state accordingly to what we express above. Even if the client, has locally the option disabled, it will, however, receive the message from the unknown contact.


TODO

Do other way around.
It works, but

I can control this state
/v2/accounts/phone_number_identity_key_distribution

SIM swapping:
  - use case: security conscious user, enabled registration lock to protect their account
  - attack: trick the server to disable the lock
  - attack2: sim "swap" to get the phone number re-registration sms



  :
- captcha request from the client(it has mitm certificate, so encrypted with that one)
- decrypt (already done) and encrypt it with the real signal certificate (swapped with the mitm signal)
- I should get the code of the captcha

Basically this is the mechanism that should be adopted for anything.

# Updates:
- Plan of action (Show picture/ scope)
- Emulate the protocol (cryptographic native function).
- Intercept requests and alter the response.
  - For now is just focused on key registration, one time keys (idenkey and signed prekey are left unchanged).
- TLS proxy related to the scope. This helps out with setup and guarantees persistent attack.