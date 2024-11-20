from typing import Optional

import pytest

import base64

from signal_protocol.address import DeviceId, ProtocolAddress
from signal_protocol.curve import KeyPair
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.protocol import PreKeySignalMessage
from signal_protocol.session import process_prekey_bundle
from signal_protocol.session_cipher import message_decrypt, message_encrypt
from signal_protocol.state import (
    PreKeyBundle,
    PreKeyId,
    PreKeyRecord,
    SessionRecord,
    SignedPreKeyId,
    SignedPreKeyRecord,
)
from signal_protocol.storage import InMemSignalProtocolStore
from sqlmodel import select

import logging

from src.constants import PRIMARY_DEVICE_ID

from db.database import ConversationSession, Device, StoreKeyRecord, User, VisitenKarte, LegitKeyRecord
from db.session import DatabaseSessionManager, Session
import json 

import signal_protocol.kem as kem

from src.mitm_interface import MitmUser, MitmVisitenKarte, VisitenKarteType

from signal_protocol.identity_key import IdentityKey
import unittest
from signal_protocol.address import DeviceId, ProtocolAddress
from signal_protocol.curve import KeyPair, PublicKey, PrivateKey
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.protocol import PreKeySignalMessage
from signal_protocol.session import process_prekey_bundle
from signal_protocol.session_cipher import message_decrypt, message_encrypt
from signal_protocol.state import (
    PreKeyBundle,
    PreKeyId,
    PreKeyRecord,
    SessionRecord,
    SignedPreKeyId,
    SignedPreKeyRecord,
    KyberPreKeyRecord,
    KyberPreKeyId,
)

from time import time

from db.dbhacks import PydanticSignedPreKey, PydanticPreKey, PydanticPqKey, _KeyRecord
from typing import get_args


@pytest.fixture
def initialize_registration_request():
    req = json.load(open("tests/fixtures/registration_request.json"))

    aci_regid = req["accountAttributes"]["registrationId"]
    aci_identity_key = IdentityKey.from_base64(req["aciIdentityKey"].encode())
    
    aci_signed_pre_key_id, aci_signed_pre_key_public_key, aci_signed_pre_key_signature = (req["aciSignedPreKey"]["keyId"], req["aciSignedPreKey"]["publicKey"], req["aciSignedPreKey"]["signature"])

    #aci_signed_pre_key_record = _KeyRecord(aci_signed_pre_key_id, PublicKey.from_base64(aci_signed_pre_key_public_key.encode()), aci_signed_pre_key_signature)

    aci_pq_last_resort_pre_key_id, aci_pq_last_resort_pre_key_public_key, aci_pq_last_resort_pre_key_signature = (req["aciPqLastResortPreKey"]["keyId"], req["aciPqLastResortPreKey"]["publicKey"], req["aciPqLastResortPreKey"]["signature"])

    # aci_pq_last_resort_pre_key_record = _KeyRecord(aci_pq_last_resort_pre_key_id, PublicKey.from_base64(aci_pq_last_resort_pre_key_public_key.encode()), aci_pq_last_resort_pre_key_signature)

    pni_regid = req["accountAttributes"]["registrationId"]
    pni_identity_key = IdentityKey.from_base64(req["pniIdentityKey"].encode())
    pni_signed_pre_key_id, pni_signed_pre_key_public_key, pni_signed_pre_key_public_key_signature = (req["pniSignedPreKey"]["keyId"], req["pniSignedPreKey"]["publicKey"], req["pniSignedPreKey"]["signature"])
    # pni_signed_pre_key_record = _KeyRecord(pni_signed_pre_key_id, PublicKey.from_base64(pni_signed_pre_key_public_key.encode()), pni_signed_pre_key_public_key_signature)

    pni_pq_last_resort_pre_key_id, pni_pq_last_resort_pre_key_public_key, pni_pq_last_resort_pre_key_signature = (req["pniPqLastResortPreKey"]["keyId"], req["pniPqLastResortPreKey"]["publicKey"], req["pniPqLastResortPreKey"]["signature"])


    return {
        "request": req,
        "socket_address": "192.168.12.158:39778",
        "aci_regid": aci_regid,
        "aci_identity_key": aci_identity_key,
        "aci_signed_pre_key_id": aci_signed_pre_key_id,
        "aci_signed_pre_key_public_key": aci_signed_pre_key_public_key,
        "aci_signed_pre_key_public_key_signature": aci_signed_pre_key_signature,
        "aci_pq_last_resort_pre_key_id": aci_pq_last_resort_pre_key_id,
        "aci_pq_last_resort_pre_key_public_key": aci_pq_last_resort_pre_key_public_key,
        "aci_pq_last_resort_pre_key_signature": aci_pq_last_resort_pre_key_signature,
        "pni_regid": pni_regid,
        "pni_identity_key": pni_identity_key,
        "pni_signed_pre_key_id": pni_signed_pre_key_id,
        "pni_signed_pre_key_public_key": pni_signed_pre_key_public_key,
        "pni_signed_pre_key_public_key_signature": pni_signed_pre_key_public_key_signature,
        "pni_pq_last_resort_pre_key_id": pni_pq_last_resort_pre_key_id,
        "pni_pq_last_resort_pre_key_public_key": pni_pq_last_resort_pre_key_public_key,
        "pni_pq_last_resort_pre_key_signature": pni_pq_last_resort_pre_key_signature,
    }

def test_registration_request_endpoint(initialize_registration_request):
    # /v1/registration request coming
    reg_req = initialize_registration_request["request"]

    # create records of legit keys uploaded by the client
    aci_legit_records = LegitKeyRecord(
        type=VisitenKarteType.ACI.value,
        uuid="",
        deviceId=1,
        registrationId= initialize_registration_request["aci_regid"],
        identityKey=IdentityKey.from_base64(reg_req["aciIdentityKey"].encode()),
        signedPreKey= _KeyRecord(reg_req["aciSignedPreKey"]["keyId"], PublicKey.from_base64(reg_req["aciSignedPreKey"]["publicKey"].encode()), reg_req["aciSignedPreKey"]["signature"]),
        PqLastResortPreKey= _KeyRecord(reg_req["aciPqLastResortPreKey"]["keyId"], kem.PublicKey.from_base64(reg_req["aciPqLastResortPreKey"]["publicKey"].encode()), reg_req["aciPqLastResortPreKey"]["signature"]),
    )

    pni_legit_records = LegitKeyRecord(
        type=VisitenKarteType.PNI.value,
        uuid="",
        deviceId=1,
        registrationId=initialize_registration_request["pni_regid"],
        identityKey=IdentityKey.from_base64(reg_req["pniIdentityKey"].encode()),
        signedPreKey= _KeyRecord(reg_req["pniSignedPreKey"]["keyId"], PublicKey.from_base64(reg_req["pniSignedPreKey"]["publicKey"].encode()), reg_req["pniSignedPreKey"]["signature"]),
        PqLastResortPreKey= _KeyRecord(reg_req["pniPqLastResortPreKey"]["keyId"], kem.PublicKey.from_base64(reg_req["pniPqLastResortPreKey"]["publicKey"].encode()), reg_req["pniPqLastResortPreKey"]["signature"]),
    )

    # commit to db
    session_manager = DatabaseSessionManager()
    session = session_manager.get_session()

    with session as s:
        s.merge(aci_legit_records)
        s.merge(pni_legit_records)

        s.commit()

    assert aci_legit_records.registration_id == initialize_registration_request["aci_regid"]

    assert aci_legit_records.identity_key == initialize_registration_request["aci_identity_key"]

    assert aci_legit_records.signed_pre_key.key_id == initialize_registration_request["aci_signed_pre_key_id"]
    assert aci_legit_records.signed_pre_key.public_key.to_base64() == initialize_registration_request["aci_signed_pre_key_public_key"]
    assert aci_legit_records.signed_pre_key.signature == initialize_registration_request["aci_signed_pre_key_public_key_signature"]

    assert aci_legit_records.last_resort_kyber_key.key_id == initialize_registration_request["aci_pq_last_resort_pre_key_id"]
    assert aci_legit_records.last_resort_kyber_key.public_key.to_base64() == initialize_registration_request["aci_pq_last_resort_pre_key_public_key"]
    assert aci_legit_records.last_resort_kyber_key.signature == initialize_registration_request["aci_pq_last_resort_pre_key_signature"]

    assert pni_legit_records.registration_id == initialize_registration_request["pni_regid"]
    
    assert pni_legit_records.identity_key == initialize_registration_request["pni_identity_key"]

    assert pni_legit_records.signed_pre_key.key_id == initialize_registration_request["pni_signed_pre_key_id"]
    assert pni_legit_records.signed_pre_key.public_key.to_base64() == initialize_registration_request["pni_signed_pre_key_public_key"]
    assert pni_legit_records.signed_pre_key.signature == initialize_registration_request["pni_signed_pre_key_public_key_signature"]

    assert pni_legit_records.last_resort_kyber_key.key_id == initialize_registration_request["pni_pq_last_resort_pre_key_id"]
    assert pni_legit_records.last_resort_kyber_key.public_key.to_base64() == initialize_registration_request["pni_pq_last_resort_pre_key_public_key"]
    assert pni_legit_records.last_resort_kyber_key.signature == initialize_registration_request["pni_pq_last_resort_pre_key_signature"]


    # update request with fake keys

    alice_aci_vk = MitmVisitenKarte(karte_type=VisitenKarteType.ACI,
                                    signed_pre_key_id=initialize_registration_request["aci_signed_pre_key_id"],
                                    last_resort_kyber_pre_key_id=initialize_registration_request["aci_pq_last_resort_pre_key_id"]
                                    )
    alice_pni_vk = MitmVisitenKarte(karte_type=VisitenKarteType.PNI, 
                                    signed_pre_key_id=initialize_registration_request["pni_signed_pre_key_id"],
                                    last_resort_kyber_pre_key_id=initialize_registration_request["pni_pq_last_resort_pre_key_id"])

    alice_fk_aci_vk = alice_aci_vk
    alice_fk_pni_vk = alice_pni_vk

    fake_aci_IdentityKey = alice_fk_aci_vk.get_identity_key().public_key().to_base64()
    fake_pni_IdentityKey = alice_fk_pni_vk.get_identity_key().public_key().to_base64()

    fake_aci_signed_pre_key = alice_fk_aci_vk.get_signed_pre_key_record()
    fake_aci_last_resort_kyber_pre_key = alice_fk_aci_vk.get_last_resort_kyber_pre_key()

    fake_pni_signed_pre_key = alice_fk_pni_vk.get_signed_pre_key_record()
    fake_pni_last_resort_kyber_pre_key = alice_fk_pni_vk.get_last_resort_kyber_pre_key()

    reg_req["aciIdentityKey"] = fake_aci_IdentityKey
    reg_req["pniIdentityKey"] = fake_pni_IdentityKey

    reg_req["aciSignedPreKey"]["publicKey"] = fake_aci_signed_pre_key.public_key().to_base64()
    reg_req["aciSignedPreKey"]["signature"] = base64.b64encode(fake_aci_signed_pre_key.signature()).decode()
    reg_req["aciSignedPreKey"]["keyId"] = fake_aci_signed_pre_key.id().get_id()

    reg_req["aciPqLastResortPreKey"]["publicKey"]= fake_aci_last_resort_kyber_pre_key.public_key().to_base64()
    reg_req["aciPqLastResortPreKey"]["signature"]= base64.b64encode(fake_aci_last_resort_kyber_pre_key.signature()).decode()
    reg_req["aciPqLastResortPreKey"]["keyId"]= fake_aci_last_resort_kyber_pre_key.id().get_id()

    reg_req["pniSignedPreKey"]["publicKey"]= fake_pni_signed_pre_key.public_key().to_base64()
    reg_req["pniSignedPreKey"]["signature"]= base64.b64encode(fake_pni_signed_pre_key.signature()).decode()
    reg_req["pniSignedPreKey"]["keyId"]= fake_pni_signed_pre_key.id().get_id()

    reg_req["pniPqLastResortPreKey"]["publicKey"] = fake_pni_last_resort_kyber_pre_key.public_key().to_base64()
    reg_req["pniPqLastResortPreKey"]["signature"] = base64.b64encode(fake_pni_last_resort_kyber_pre_key.signature()).decode()
    reg_req["pniPqLastResortPreKey"]["keyId"] = fake_pni_last_resort_kyber_pre_key.id().get_id()

    # alice_fake_aci_vk = StoreKeyRecord()

    assert reg_req["aciIdentityKey"] != initialize_registration_request["aci_identity_key"]
    assert reg_req["pniIdentityKey"] != initialize_registration_request["pni_identity_key"]
    
    assert reg_req["aciSignedPreKey"]["publicKey"] != initialize_registration_request["aci_signed_pre_key_public_key"]
    assert reg_req["aciSignedPreKey"]["signature"] != initialize_registration_request["aci_signed_pre_key_public_key_signature"]
    assert reg_req["aciSignedPreKey"]["keyId"] == initialize_registration_request["aci_signed_pre_key_id"]

    assert reg_req["aciPqLastResortPreKey"]["publicKey"] != initialize_registration_request["aci_pq_last_resort_pre_key_public_key"]
    assert reg_req["aciPqLastResortPreKey"]["signature"] != initialize_registration_request["aci_pq_last_resort_pre_key_signature"]
    assert reg_req["aciPqLastResortPreKey"]["keyId"] == initialize_registration_request["aci_pq_last_resort_pre_key_id"]

    assert reg_req["pniSignedPreKey"]["publicKey"] != initialize_registration_request["pni_signed_pre_key_public_key"]
    assert reg_req["pniSignedPreKey"]["signature"] != initialize_registration_request["pni_signed_pre_key_public_key_signature"]
    assert reg_req["pniSignedPreKey"]["keyId"] == initialize_registration_request["pni_signed_pre_key_id"]

    assert reg_req["pniPqLastResortPreKey"]["publicKey"] != initialize_registration_request["pni_pq_last_resort_pre_key_public_key"]
    assert reg_req["pniPqLastResortPreKey"]["signature"] != initialize_registration_request["pni_pq_last_resort_pre_key_signature"]
    assert reg_req["pniPqLastResortPreKey"]["keyId"] == initialize_registration_request["pni_pq_last_resort_pre_key_id"]

    ## Should I save the legit keys in the DB or should I just keep them in memory?


@pytest.fixture
def initialize_registration_response() -> dict[dict, str, MitmVisitenKarte, MitmVisitenKarte]:
    resp = json.load(open("tests/fixtures/registration_response.json"))

    alice_aci_vk = MitmVisitenKarte(VisitenKarteType.ACI)
    alice_pni_vk = MitmVisitenKarte(VisitenKarteType.PNI)

    return {
        "response": resp,
        "socket_address": "192.168.12.158:39778",
        "alice_aci_vk": alice_aci_vk,
        "alice_pni_vk": alice_pni_vk,
        }

def test_registration_response_endpoint(initialize_registration_request, initialize_registration_response):

    # /v1/registration response coming
    req = initialize_registration_request["request"]
    resp = initialize_registration_response["response"]
    socket_address = initialize_registration_response["socket_address"]
    alice_aci_vk = initialize_registration_response["alice_aci_vk"]
    alice_pni_vk = initialize_registration_response["alice_pni_vk"]


    alice = MitmUser(protocol_address= ProtocolAddress(resp["number"], 1), aci_uuid= resp["uuid"], pni_uuid=resp["pni"], aci_visitenkarte=alice_aci_vk, pni_visitenkarte=alice_pni_vk)
    
    # Retrieve the legit keys from the db

    ## Should I save the legit keys in the DB or should I just keep them in memory?

def test_registration_request_and_response(initialize_registration_request, initialize_registration_response):
    pass

@pytest.fixture
def initialize_keys_upload_request() -> dict[dict, MitmUser]:
    req = json.load(open("tests/fixtures/aci_keys.json"))

    #alice = MitmUser(protocol_address= ProtocolAddress("alice", 1), aci_uuid="alice_aci", pni_uuid="alice_pni")

    return {
        "request": req,
    #    "victim": alice,
    }

def test_keys_upload(initialize_registration_request, initialize_registration_response, initialize_keys_upload_request):
    
    reg_request = initialize_registration_request["request"]
    reg_response = initialize_registration_response["response"]
    
    keys_upload_request = initialize_keys_upload_request["request"]

    alice_aci_vk = MitmVisitenKarte(VisitenKarteType.ACI,
                                    signed_pre_key_id=initialize_registration_request["aci_signed_pre_key_id"],
                                    last_resort_kyber_pre_key_id=initialize_registration_request["aci_pq_last_resort_pre_key_id"],
                                    first_pre_key_record_id= keys_upload_request["preKeys"][0]["keyId"],
                                    first_kyber_pre_key_record_id= keys_upload_request["pqPreKeys"][0]["keyId"],
                                    )
    
    alice_pni_vk = MitmVisitenKarte(VisitenKarteType.PNI,
                                    signed_pre_key_id=initialize_registration_request["pni_signed_pre_key_id"],
                                    last_resort_kyber_pre_key_id=initialize_registration_request["pni_pq_last_resort_pre_key_id"],
                                    first_pre_key_record_id= keys_upload_request["preKeys"][0]["keyId"],
                                    first_kyber_pre_key_record_id= keys_upload_request["pqPreKeys"][0]["keyId"],
                                    )
    
    alice = MitmUser(protocol_address= ProtocolAddress(reg_response["number"], 1),
                    aci_uuid= reg_response["uuid"], 
                    pni_uuid=reg_response["pni"], 
                    aci_visitenkarte=alice_aci_vk,
                    pni_visitenkarte=alice_pni_vk,
                    phone_number=reg_response["number"],
                    unidentified_accesss_key= reg_request["accountAttributes"]["unidentifiedAccessKey"]
                    )
    
    assert alice.get_aci_visitenkarte().get_pre_key_records()[0].id().get_id() == keys_upload_request["preKeys"][0]["keyId"]
    assert alice.get_aci_visitenkarte().get_kyber_pre_key_records()[0].id().get_id() == keys_upload_request["pqPreKeys"][0]["keyId"]

    # create records of legit keys uploaded by the client

    aci_legit_records = LegitKeyRecord(
        type=VisitenKarteType.ACI.value,
        uuid= reg_response["uuid"],
        deviceId=1,
        registrationId= initialize_registration_request["aci_regid"],
        identityKey=IdentityKey.from_base64(reg_request["aciIdentityKey"].encode()),
        signedPreKey= _KeyRecord(reg_request["aciSignedPreKey"]["keyId"], PublicKey.from_base64(reg_request["aciSignedPreKey"]["publicKey"].encode()), reg_request["aciSignedPreKey"]["signature"]),
        PqLastResortPreKey= _KeyRecord(reg_request["aciPqLastResortPreKey"]["keyId"], kem.PublicKey.from_base64(reg_request["aciPqLastResortPreKey"]["publicKey"].encode()), reg_request["aciPqLastResortPreKey"]["signature"]),
        preKey= []
    )

    
    pass

    # update request with fake keys

    