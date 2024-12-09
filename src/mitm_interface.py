from random import random, randint

from db.database import VisitenKarte, User, Device, ConversationSession, StoreKeyRecord, LegitKeyRecord
from db.session import DatabaseSessionManager
from db.database import create_tables

from signal_protocol import (
    identity_key,
    storage,
    protocol,
    session_cipher,
    session,
    state,
    kem,
    helpers,
)
from signal_protocol.kem import KeyType

from signal_protocol.address import ProtocolAddress, DeviceId
from signal_protocol.state import (
    PreKeyId,
    KyberPreKeyId,
    SignedPreKeyId,
    SignedPreKeyRecord,
    PreKeyBundle,
    PreKeyRecord,
    KyberPreKeyRecord,
    SessionRecord,
)

import base64

from signal_protocol.curve import KeyPair, PublicKey
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.error import SignalProtocolException

from signal_protocol.protocol import CiphertextMessage
from protos.gen.SignalService_pb2 import Content


from db.dbhacks import PydanticIdentityKeyPair

from time import time
import src.utils as utils

from enum import Enum
import logging

# create_tables()

from signal_protocol.identity_key import IdentityKeyPair


class VisitenKarteType(Enum):
    ACI = "aci"
    PNI = "pni"


class MitmVisitenKarte:
    def __init__(
        self,
        karte_type: VisitenKarteType,
        uuid: str | None = None,
        device_id: int | None = None,
        registration_id: int | None = None,
        identity_key: IdentityKeyPair | None = None,
        signed_pre_key_id: int | None = None,
        signed_pre_key_record: SignedPreKeyRecord | None = None,
        last_resort_kyber_pre_key_id: int | None = None,
        last_resort_kyber_pre_key: KyberPreKeyRecord | None = None,
        first_pre_key_record_id: int | None = None,
        pre_key_records: list[PreKeyRecord] | None = None,
        first_kyber_pre_key_record_id: int | None = None,
        kyber_pre_key_records: list[KyberPreKeyRecord] | None = None,
    ):

        self._uuid = uuid if uuid else ""
        self._device_id = device_id if device_id else 1
        self._registration_id = registration_id if registration_id else randint(1, 2**14)
        self._identity_key: PydanticIdentityKeyPair = identity_key if identity_key else IdentityKeyPair.generate()
        self._karte_type = karte_type

        self._signed_pre_key_record = signed_pre_key_record or (self._generate_signed_pre_key_record() if not signed_pre_key_id else self._generate_signed_pre_key_record(signed_pre_key_id))
        self._last_resort_kyber_pre_key = last_resort_kyber_pre_key or (self._generate_last_resort_kyber_pre_key() if not last_resort_kyber_pre_key_id else self._generate_last_resort_kyber_pre_key(last_resort_kyber_pre_key_id))
        self._pre_key_records = pre_key_records or (state.generate_n_prekeys(100, PreKeyId(randint(1, 2**14 - 100))if not first_pre_key_record_id else state.generate_n_prekeys(100, PreKeyId(first_pre_key_record_id))))
        self._kyber_pre_key_records = kyber_pre_key_records or (state.generate_n_signed_kyberkeys(
            100, KyberPreKeyId(randint(1, 2**14 - 100)), self._identity_key.private_key()
        ) if not first_kyber_pre_key_record_id else state.generate_n_signed_kyberkeys(100, KyberPreKeyId(first_kyber_pre_key_record_id), self._identity_key.private_key()))

        assert self._signed_pre_key_record.id().get_id() == signed_pre_key_id if signed_pre_key_id else True
        assert self._last_resort_kyber_pre_key.id().get_id() == last_resort_kyber_pre_key_id if last_resort_kyber_pre_key_id else True
        assert self._pre_key_records[0].id().get_id() == first_pre_key_record_id if first_pre_key_record_id else True
        assert self._kyber_pre_key_records[0].id().get_id() == first_kyber_pre_key_record_id if first_kyber_pre_key_record_id else True

        self._store = storage.InMemSignalProtocolStore(self._identity_key, self._registration_id)

        # Save the generated keys to the store
        self._store.save_signed_pre_key(self._signed_pre_key_record.id(), self._signed_pre_key_record)
        self._store.save_kyber_pre_key(self._last_resort_kyber_pre_key.id(), self._last_resort_kyber_pre_key)
        for pre_key in self._pre_key_records:
            self._store.save_pre_key(pre_key.id(), pre_key)
        for kyber_pre_key in self._kyber_pre_key_records:
            self._store.save_kyber_pre_key(kyber_pre_key.id(), kyber_pre_key)

        # self._save_visitenkarte()
        # self._save_keys()

        # Export keys and save them in the database

    def _generate_signed_pre_key_record(self, id = 0):
        signed_pre_key_id = SignedPreKeyId(randint(1, 2**14)) if not id else SignedPreKeyId(id)
        signed_pre_key_pair = KeyPair.generate()
        signed_pre_key_signature = self._identity_key.private_key().calculate_signature(
            signed_pre_key_pair.public_key().serialize()
        )
        return SignedPreKeyRecord(signed_pre_key_id, int(time()), signed_pre_key_pair, signed_pre_key_signature)

    def _generate_last_resort_kyber_pre_key(self, id = 0):
        kem_type = KeyType(0)
        last_resort_kyber_pre_key_id = KyberPreKeyId(randint(1, 2**14)) if not id else KyberPreKeyId(id)
        return KyberPreKeyRecord.generate(kem_type, last_resort_kyber_pre_key_id, self._identity_key.private_key())

    def _save_visitenkarte(self):
        # Save the visitenkarte info to database
        with DatabaseSessionManager().get_session() as session:

            visitenKarte = VisitenKarte(
                type=self._karte_type.value,
                uuid=self._uuid,
                device_id=self._device_id,
                identityKey=self._identity_key,
                registration_id=self._registration_id,
            )
            session.merge(visitenKarte)
            session.commit()

    def _save_keys(self):

        with DatabaseSessionManager().get_session() as session:

            # TODO: just current signed_pre_key or all signed_pre_keys including past ones?
            spk_ids = [id for id in self._store.all_signed_pre_key_ids()]
            spk = self._store.get_signed_pre_key(spk_ids[0])
            # spk = [self._store.get_signed_pre_key(id) for id in spk_ids]

            opk_ids = [id for id in self._store.all_pre_key_ids()]
            opk = [self._store.get_pre_key(id) for id in opk_ids]

            kyber_opk_ids = [id for id in self._store.all_kyber_pre_key_ids()]
            kyber_opk = [self._store.get_kyber_pre_key(id) for id in kyber_opk_ids]

            store_key_records = StoreKeyRecord(
                uuid=self._uuid,
                deviceId=self._device_id,
                identityKey=self._identity_key,
                registrationId=self._registration_id,
                signedPreKey=spk,
                preKeys=opk,
                kyberPreKeys=kyber_opk,
                pqLastResortPreKey=self._last_resort_kyber_pre_key,
            )
            session.merge(store_key_records)

            #logging.info(f"Saved keys for {store_key_records}")

            session.commit()
            
    def get_uuid(self):
        return self._uuid
    
    def get_device_id(self):
        return self._device_id

    def get_store(self):
        return self._store

    def get_identity_key(self):
        return self._identity_key

    def get_registration_id(self):
        return self._registration_id

    def get_karte_type(self):
        return self._karte_type

    def get_signed_pre_key_record(self):
        return self._signed_pre_key_record

    def get_pre_key_records(self):
        return self._pre_key_records

    def get_kyber_pre_key_records(self):
        return self._kyber_pre_key_records

    def get_last_resort_kyber_pre_key(self):
        return self._last_resort_kyber_pre_key

    def get_pre_key_record(self, pre_key_id: PreKeyId):
        return self._store.get_pre_key(pre_key_id)

    def get_kyber_pre_key_record(self, kyber_pre_key_id: KyberPreKeyId):
        return self._store.get_kyber_pre_key(kyber_pre_key_id)
    
    def serialize_pre_keys(self) -> list[dict]:
        ### TODO: do this in Rust

        pre_keys = []
        for pre_key in self._pre_key_records:
            pre_keys.append({
                "keyId": pre_key.id().get_id(),
                "publicKey": pre_key.public_key().to_base64()
                })
        return pre_keys
    
    def serialize_kyber_pre_keys(self) -> list[dict]:
        ### TODO: do this in Rust
        kyber_pre_keys = []
        for kyber_pre_key in self._kyber_pre_key_records:
            kyber_pre_keys.append({
                "keyId": kyber_pre_key.id().get_id(),
                "publicKey": kyber_pre_key.public_key().to_base64(),
                "signature": base64.b64encode(kyber_pre_key.signature()).decode()
                })
        return kyber_pre_keys

    def update_signed_pre_key(self, id: int = 0):
        self._signed_pre_key_record = self._generate_signed_pre_key_record(id)
        self._store.save_signed_pre_key(self._signed_pre_key_record.id(), self._signed_pre_key_record)
        #self._save_keys()

    def update_last_resort_kyber_pre_key(self, id: int = 0):
        self._last_resort_kyber_pre_key = self._generate_last_resort_kyber_pre_key(id)
        self._store.save_kyber_pre_key(self._last_resort_kyber_pre_key.id(), self._last_resort_kyber_pre_key)
        #self._save_keys()

    def update_pre_keys(self, id: int = 0):
        self._pre_key_records = state.generate_n_prekeys(100, PreKeyId(randint(1, 2**14 - 100))) if not id else state.generate_n_prekeys(100, PreKeyId(id))
        for pre_key in self._pre_key_records:
            self._store.save_pre_key(pre_key.id(), pre_key)
        #self._save_keys()

    def update_kyber_pre_keys(self, id: int= 0):
        self._kyber_pre_key_records = state.generate_n_signed_kyberkeys(
            100, KyberPreKeyId(randint(1, 2**14 - 100)), self._identity_key.private_key()
        ) if not id else state.generate_n_signed_kyberkeys(100, KyberPreKeyId(id), self._identity_key.private_key())
        for kyber_pre_key in self._kyber_pre_key_records:
            self._store.save_kyber_pre_key(kyber_pre_key.id(), kyber_pre_key)
        #self._save_keys()


    @staticmethod
    def retrieve_visiten_karte(self, uuid: str, device_id: int):
        with DatabaseSessionManager().get_session() as session:
            visitenkarte = VisitenKarte.retrieve_visitenkarte(session, uuid, device_id)
            store_key_record = StoreKeyRecord.retrieve_store_key_record(session, uuid, device_id)

            vk = self.__init__(karte_type=visitenkarte.type, 
                                uuid= visitenkarte.uuid, 
                                device_id=visitenkarte.device_id, 
                                registration_id=visitenkarte.registration_id, 
                                identity_key=store_key_record.get_identity_keypair(session, uuid, device_id), 
                                signed_pre_key_id=store_key_record.local_spk_record.id().get_id(),
                                signed_pre_key_record=store_key_record.local_spk_record, 
                                last_resort_kyber_pre_key_id=store_key_record.local_last_resort_kyber_key.id().get_id(), 
                                last_resort_kyber_pre_key=store_key_record, 
                                first_pre_key_record_id=store_key_record.local_pre_keys[0].key_id(), 
                                pre_key_records=store_key_record.local_pre_keys, 
                                first_kyber_pre_key_record_id=store_key_record.local_kyber_pre_keys[0].id().get_id(), 
                                kyber_pre_key_records=store_key_record.local_kyber_pre_keys)

            return vk

class MitmUser:
    """
    MitmUser class represents the victim to the outside world.
    Attributes:
        _protocol_address (ProtocolAddress): The protocol address of the user.
        _aci_store (MitmVisitenKarte): The ACI store associated with the user.
        _pni_store (MitmVisitenKarte): The PNI store associated with the user.
    """

    def __init__(
        self,
        protocol_address: ProtocolAddress,
        aci_uuid: str,
        pni_uuid: str,
        aci_visitenkarte: MitmVisitenKarte | None = None,
        pni_visitenkarte: MitmVisitenKarte | None = None,
        phone_number: str | None = None,
        unidentified_accesss_key: str | None = None,
    ):
        
        self._phone_number = phone_number
        self._unidentified_access_key = unidentified_accesss_key
        self._protocol_address = protocol_address
        self._aci_visitenkarte = (
            MitmVisitenKarte(VisitenKarteType.ACI, aci_uuid) if not aci_visitenkarte else aci_visitenkarte
        )
        self._pni_visitenkarte = (
            MitmVisitenKarte(VisitenKarteType.PNI, pni_uuid) if not pni_visitenkarte else pni_visitenkarte
        )

    def save_user(self):
        with DatabaseSessionManager().get_session() as session:
            user = User(
                aci=self._aci_visitenkarte.get_uuid(),
                pni=self._pni_visitenkarte.get_uuid(),
                phone_number= self._phone_number,
                aci_identity_key=self._aci_visitenkarte.get_identity_key(),
                pni_identity_key=self._pni_visitenkarte.get_identity_key(),
                is_victim=True,
                unidentified_access_key=self._unidentified_access_key,
            )

            device = Device(
                user=user,
                device_id=self._protocol_address.device_id(),
                aci=self._aci_visitenkarte.get_uuid(),
                pni=self._pni_visitenkarte.get_uuid(),
            )

            self._aci_visitenkarte._save_visitenkarte()
            self._pni_visitenkarte._save_visitenkarte()     

            self._aci_visitenkarte._save_keys()
            self._pni_visitenkarte._save_keys()

            session.merge(user)
            session.merge(device)
            session.commit()

    def get_visitenkarte(self, store_type: VisitenKarteType) -> MitmVisitenKarte:
        if store_type == VisitenKarteType.ACI:
            return self._aci_visitenkarte
        elif store_type == VisitenKarteType.PNI:
            return self._pni_visitenkarte
        else:
            raise SignalProtocolException(f"Invalid store type: {store_type}")

    def get_registration_id(self, store_type: VisitenKarteType) -> int:
        return self.get_visitenkarte(store_type).get_registration_id()

    def get_identity_key(self, store_type: VisitenKarteType) -> IdentityKeyPair:
        return self.get_visitenkarte(store_type).get_identity_key()

    def get_signed_pre_key_record(self, store_type: VisitenKarteType) -> SignedPreKeyRecord:
        return self.get_visitenkarte(store_type).get_signed_pre_key_record()

    def get_pre_key_record(self, store_type: VisitenKarteType, pre_key_id: PreKeyId | None = None) -> PreKeyRecord:
        pkr = (
            self.get_visitenkarte(store_type).get_pre_key_record(pre_key_id)
            if pre_key_id
            else self.get_visitenkarte(store_type).get_pre_key_records()[0]
        )
        return pkr

    def get_kyber_pre_key_record(
        self, store_type: VisitenKarteType, kyber_pre_key_id: KyberPreKeyId | None = None
    ) -> KyberPreKeyRecord:
        # TODO: mark the kyber keys?
        kpkr = (
            self.get_visitenkarte(store_type).get_kyber_pre_key_record(kyber_pre_key_id)
            if kyber_pre_key_id
            else self.get_visitenkarte(store_type).get_kyber_pre_key_records()[0]
        )
        # self.get_store(store_type)._store.mark_kyber_pre_key_as_used(kpkr.id())
        return kpkr

    def get_protocol_address(self) -> ProtocolAddress:
        return self._protocol_address

    def get_aci_visitenkarte(self) -> MitmVisitenKarte:
        return self._aci_visitenkarte

    def get_pni_visitenkarte(self) -> MitmVisitenKarte:
        return self._pni_visitenkarte

    def update_visitenkarte(self, store_type: VisitenKarteType, store: MitmVisitenKarte):
        if store_type == VisitenKarteType.ACI:
            self._aci_visitenkarte = store
        elif store_type == VisitenKarteType.PNI:
            self._pni_visitenkarte = store
        else:
            raise SignalProtocolException(f"Invalid store type: {store_type}")


    def generate_pre_key_bundle(self, store_type: VisitenKarteType) -> PreKeyBundle:
        pkb = PreKeyBundle(
            self.get_registration_id(store_type),
            DeviceId(self.get_protocol_address().device_id()),
            (self.get_pre_key_record(store_type).id(), self.get_pre_key_record(store_type).public_key()),
            self.get_signed_pre_key_record(store_type).id(),
            self.get_signed_pre_key_record(store_type).public_key(),
            self.get_signed_pre_key_record(store_type).signature(),
            self.get_identity_key(store_type).identity_key(),
        )

        pkb.with_kyber_pre_key(
            self.get_kyber_pre_key_record(store_type).id(),
            self.get_kyber_pre_key_record(store_type).public_key(),
            self.get_kyber_pre_key_record(store_type).signature(),
        )

        return pkb

    def process_pre_key_bundle(
        self, store_type: VisitenKarteType, address: ProtocolAddress, pre_key_bundle: PreKeyBundle
    ):
        session.process_prekey_bundle(address, self.get_visitenkarte(store_type).get_store(), pre_key_bundle)

    def encrypt(self, karte_type: VisitenKarteType, address: ProtocolAddress, plaintext: bytes) -> CiphertextMessage:
        # if self.fakeAliceStore is None:
        #     logging.warning("Cannot encrypt to Bob(s). The outbound store was not initialized!!")

        padded_ptxt = utils.PushTransportDetails().get_padded_message_body(plaintext)
        return session_cipher.message_encrypt(self.get_visitenkarte(karte_type).get_store(), address, padded_ptxt)

    def decrypt(self, karte_type: VisitenKarteType, address: ProtocolAddress, ciphertext: CiphertextMessage | bytes) -> bytes:
        if isinstance(ciphertext, bytes):
            try:
                ciphertext = protocol.PreKeySignalMessage.try_from(ciphertext)
            except SignalProtocolException as e:
                logging.warning(f"{e}")
                return

        ptxt = session_cipher.message_decrypt(self.get_visitenkarte(karte_type).get_store(), address, ciphertext)

        ptxt = utils.PushTransportDetails().get_stripped_padding_message_body(ptxt)
        print(f"Decrypted message: {ptxt}")
        return ptxt
    
    @classmethod
    def retrieve_user_by_aci(self, aci: str):
        with DatabaseSessionManager().get_session() as session:
            user_db = User.retrieve_user_by_aci(session, aci)
            device_db = Device.retrieve_device(session, aci, 1)
            aci_visitenkarte = MitmVisitenKarte.retrieve_visiten_karte(session, aci, 1)
            pni_visitenkarte = MitmVisitenKarte.retrieve_visiten_karte(session, user_db.pni, 1)

            user = self.__init__(
                protocol_address=ProtocolAddress(user_db.aci, device_db.device_id),
                aci_uuid=user_db.aci,
                pni_uuid=user_db.pni,
                aci_visitenkarte=aci_visitenkarte,
                pni_visitenkarte=pni_visitenkarte,
                phone_number=user_db.phone_number,
                unidentified_accesss_key=user_db.unidentified_access_key
            )
            return user


class MitmSession:

    def __init__(self, sender: MitmUser, receiver: MitmUser):
        self._sender = sender
        self._receiver = receiver

    def get_session_builder(self):
        return self._session_builder

    def get_sender(self):
        return self._sender

    def get_receiver(self):
        return self._receiver

    def get_cipher(self):
        return self._sender.get_session_cipher()

    def establish_session(self, sender_store_type: VisitenKarteType, receiver_store_type: VisitenKarteType, sender_message: bytes):
        sender_store  = self._sender.get_visitenkarte(sender_store_type)
        receiver_store = self._receiver.get_visitenkarte(receiver_store_type)

        # Create a half-MitM session with fake sender and legit receiver
        with DatabaseSessionManager().get_session() as session:
            legit_receiver_record = LegitKeyRecord.get_keys(session, receiver_store.get_uuid(), receiver_store.get_device_id())

            legit_receiver_bundle = PreKeyBundle(
                registration_id= receiver_store.get_registration_id(),
                device_id= self._receiver.get_protocol_address().device_id(),
                pre_key_public= legit_receiver_record
            )


class MitmConversationSession:
    def __init__(self, local_uuid: str, local_deviceId: int, other_uuid: str, other_id: int, session: SessionRecord):
        self._session = session
        self._session_builder = session.get_session_builder()
        self._session_cipher = session.get_cipher()

    def get_session_builder(self):
        return self._session_builder

    def get_session_cipher(self):
        return self._session_cipher

    def get_sender(self):
        return self._session.get_sender()

    def get_receiver(self):
        return self._session.get_receiver()

    def get_registration_id(self):
        return self._session.get_registration_id()

    def get_identity_key(self):
        return self._session.get_identity_key()

    def get_signed_pre_key_record(self):
        return self._session.get_signed_pre_key_record()

    def get_signed_pre_key_id(self):
        return self._session.get_signed_pre_key_id()


# with DatabaseSessionManager().get_session() as session:
#     identity_key_pair = IdentityKeyPair.generate()
#     new_entry = MitmBundle(type="aci", aci="exampleAci", device_id=1, fake_identity_key_pair=identity_key_pair)
#     session.merge(new_entry)
#     session.commit()

#     result = MitmBundle.get_identity_keypair(session, "aci", "exampleAci", 1)

#     res = MitmBundle.get_signed_pre_key_pair(session, "aci", "exampleAci", 1)
#     print(f"Query Result (identity keypair): {result}")