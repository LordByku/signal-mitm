from random import random, randint

from database import VisitenKarte, User, Device, ConversationSession, StoreKeyRecord, LegitKeyRecord
from session import DatabaseSessionManager
from database import create_tables

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

from signal_protocol.curve import KeyPair, PublicKey
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.error import SignalProtocolException

from signal_protocol.protocol import CiphertextMessage
from protos.gen.SignalService_pb2 import Content


from dbhacks import PydanticIdentityKeyPair

from time import time
import utils

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
        signed_pre_key_record: SignedPreKeyRecord | None = None,
        last_resort_kyber_pre_key: KyberPreKeyRecord | None = None,
        pre_key_records: list[PreKeyRecord] | None = None,
        kyber_pre_key_records: list[KyberPreKeyRecord] | None = None,
    ):

        self._uuid = uuid if uuid else ""
        self._device_id = device_id if device_id else 1
        self._registration_id = registration_id if registration_id else randint(1, 2**14)
        self._identity_key: PydanticIdentityKeyPair = identity_key if identity_key else IdentityKeyPair.generate()
        self._karte_type = karte_type

        self._save_visitenkarte()

        self._signed_pre_key_record = signed_pre_key_record or self._generate_signed_pre_key_record()
        self._last_resort_kyber_pre_key = last_resort_kyber_pre_key or self._generate_last_resort_kyber_pre_key()
        self._pre_key_records = pre_key_records or state.generate_n_prekeys(100, PreKeyId(randint(1, 2**14 - 100)))
        self._kyber_pre_key_records = kyber_pre_key_records or state.generate_n_signed_kyberkeys(
            100, KyberPreKeyId(randint(1, 2**14 - 100)), self._identity_key.private_key()
        )

        self._store = storage.InMemSignalProtocolStore(self._identity_key, self._registration_id)

        # Save the generated keys to the store
        self._store.save_signed_pre_key(self._signed_pre_key_record.id(), self._signed_pre_key_record)
        self._store.save_kyber_pre_key(self._last_resort_kyber_pre_key.id(), self._last_resort_kyber_pre_key)
        for pre_key in self._pre_key_records:
            self._store.save_pre_key(pre_key.id(), pre_key)
        for kyber_pre_key in self._kyber_pre_key_records:
            self._store.save_kyber_pre_key(kyber_pre_key.id(), kyber_pre_key)

        self._save_keys()

        # Export keys and save them in the database

    def _generate_signed_pre_key_record(self):
        signed_pre_key_id = SignedPreKeyId(randint(1, 2**14))
        signed_pre_key_pair = KeyPair.generate()
        signed_pre_key_signature = self._identity_key.private_key().calculate_signature(
            signed_pre_key_pair.public_key().serialize()
        )
        return SignedPreKeyRecord(signed_pre_key_id, int(time()), signed_pre_key_pair, signed_pre_key_signature)

    def _generate_last_resort_kyber_pre_key(self):
        kem_type = KeyType(0)
        last_resort_kyber_pre_key_id = KyberPreKeyId(randint(1, 2**14))
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
                preKey=opk,
                kyberPreKey=kyber_opk,
                lastResortKyberPreKey=self._last_resort_kyber_pre_key,
            )
            session.merge(store_key_records)
            session.commit()

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

    def update_signed_pre_key(self):
        self._signed_pre_key_record = self._generate_signed_pre_key_record()
        self._store.save_signed_pre_key(self._signed_pre_key_record.id(), self._signed_pre_key_record)
        self._save_keys()

    def update_last_resort_kyber_pre_key(self):
        self._last_resort_kyber_pre_key = self._generate_last_resort_kyber_pre_key()
        self._store.save_kyber_pre_key(self._last_resort_kyber_pre_key.id(), self._last_resort_kyber_pre_key)
        self._save_keys()

    def update_pre_keys(self):
        self._pre_key_records = state.generate_n_prekeys(100, PreKeyId(randint(1, 2**14 - 100)))
        for pre_key in self._pre_key_records:
            self._store.save_pre_key(pre_key.id(), pre_key)
        self._save_keys()

    def update_kyber_pre_keys(self):
        self._kyber_pre_key_records = state.generate_n_signed_kyberkeys(
            100, KyberPreKeyId(randint(1, 2**14 - 100)), self._identity_key.private_key()
        )
        for kyber_pre_key in self._kyber_pre_key_records:
            self._store.save_kyber_pre_key(kyber_pre_key.id(), kyber_pre_key)
        self._save_keys()


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
    ):
        self._protocol_address = protocol_address
        self._aci_visitenkarte = (
            MitmVisitenKarte(VisitenKarteType.ACI, aci_uuid) if not aci_visitenkarte else aci_visitenkarte
        )
        self._pni_visitenkarte = (
            MitmVisitenKarte(VisitenKarteType.PNI, pni_uuid) if not pni_visitenkarte else pni_visitenkarte
        )

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


# class MitmSession:
#     def __init__(self, sender: MitmUser, receiver: MitmUser):
#         self._sender = sender
#         self._receiver = receiver
#         self._session_builder = session.SessionBuilder(
#             self._sender.get_visitenkarte().get_store(), self._receiver.get_protocol_address()
#         )

#     def get_session_builder(self):
#         return self._session_builder

#     def get_sender(self):
#         return self._sender

#     def get_receiver(self):
#         return self._receiver

#     def get_cipher(self):
#         return self._sender.get_session_cipher()

#     def get_registration_id(self):
#         return self._sender.get_registration_id()

#     def get_identity_key(self):
#         return self._sender.get_identity_key()

#     def get_signed_pre_key_record(self):
#         return self._sender.get_signed_pre_key_record()

#     def get_signed_pre_key_id(self):
#         return self._sender.get_signed_pre_key_id()


# class MitmConversationSession:
#     def __init__(self, local_uuid: str, local_deviceId: int, other_uuid: str, other_id: int, session: SessionRecord):
#         self._session = session
#         self._session_builder = session.get_session_builder()
#         self._session_cipher = session.get_cipher()

#     def get_session_builder(self):
#         return self._session_builder

#     def get_session_cipher(self):
#         return self._session_cipher

#     def get_sender(self):
#         return self._session.get_sender()

#     def get_receiver(self):
#         return self._session.get_receiver()

#     def get_registration_id(self):
#         return self._session.get_registration_id()

#     def get_identity_key(self):
#         return self._session.get_identity_key()

#     def get_signed_pre_key_record(self):
#         return self._session.get_signed_pre_key_record()

#     def get_signed_pre_key_id(self):
#         return self._session.get_signed_pre_key_id()


# with DatabaseSessionManager().get_session() as session:
#     identity_key_pair = IdentityKeyPair.generate()
#     new_entry = MitmBundle(type="aci", aci="exampleAci", device_id=1, fake_identity_key_pair=identity_key_pair)
#     session.merge(new_entry)
#     session.commit()

#     result = MitmBundle.get_identity_keypair(session, "aci", "exampleAci", 1)

#     res = MitmBundle.get_signed_pre_key_pair(session, "aci", "exampleAci", 1)
#     print(f"Query Result (identity keypair): {result}")
