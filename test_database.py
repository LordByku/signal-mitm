from database import VisitenKarte, User, Device, ConversationSession, StoreKeyRecord, LegitKeyRecord
from session import DatabaseSessionManager

import json

from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.state import SessionRecord
# Example: Inserting a new MitM bundle and retrieving it

with DatabaseSessionManager().get_session() as session:
    aci_identity_key_pair = IdentityKeyPair.generate()
    pni_identity_key_pair = IdentityKeyPair.generate()

    alice = User(
        aci="aci",
        pni="pni",
        phone_number="+1234567890",
        aci_identity_key=aci_identity_key_pair,
        pni_identity_key=pni_identity_key_pair,
        is_victim=True,
        unidentified_access_key="unidentified_access_key",
    )

    alice_primary_device = Device(
        aci ="aci",
        pni="pni",
        device_id=1,
        user=alice,
    )

    alice_vk = VisitenKarte(
        type="aci",
        registration_id=1,
        uuid="alice",
        device_id="1",
        identityKey=aci_identity_key_pair,
    )

    alice_store_key_record = StoreKeyRecord(
        uuid="aci",
        deviceId=1,
        identityKey=aci_identity_key_pair,
        registrationId=1,
    )

    session_record = SessionRecord.new_fresh()

    alice_convo = ConversationSession(
        store_uuid="aci",
        store_device_id=1,
        other_service_id="bob",
        other_device_id=1,
        identityKey=aci_identity_key_pair.public_key(),
        session_record=session_record,
    )

    with open("debug/bundle.json") as f:
        bundle = json.load(f)
        bundle["devices"][0]["identityKey"] = bundle["identityKey"]
        bundle = bundle["devices"][0]
        bundle["uuid"] = "test1"
        bundle["type"] = "aci"
        bundle["preKey"] = [bundle["preKey"]]
        bundle["pqPreKey"] = [bundle["pqPreKey"]]

        print(bundle)
        # bundle["identityKey"]
        lb = LegitKeyRecord.model_validate(bundle)
        print(lb)
        print(lb.model_dump_json(indent=2, by_alias=True))

        print(lb.identity_key)
        print(lb.signed_pre_key.public_key)

    session.merge(alice)
    session.merge(alice_primary_device)
    session.merge(alice_vk)
    session.merge(alice_store_key_record)
    session.merge(alice_convo)
    session.merge(lb)

    session.commit()

    result = VisitenKarte.get_identity_keypair(session, "aci", "alice" , 1)
    print(f"Query Result (identity keypair): {result}")