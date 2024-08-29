import json
import logging

from jsonschema import (
    validate,
    ValidationError,
)  # todo: Handle ValidationError properly
from typing import Union

import db_json_schemas
from db_json_schemas import (
    Fake_key_schema,
    Fake_key_array_schema,
    Fake_key_schema_signed,
    Fake_key_array_schema_signed,
)
from peewee import *
from playhouse.sqlite_ext import SqliteExtDatabase, JSONField

# TODO: Remove relationship of pni Device and pni User

DB_NAME = "mitm.db"

# database = SqliteDatabase(DB_NAME)
database = SqliteExtDatabase(DB_NAME)
database.connect()


class BaseSqliteModel(Model):
    class Meta:
        database = database


class User(BaseSqliteModel):
    pNumber = CharField(null=True)
    aci = CharField(null=True, primary_key=True)
    pni = CharField(null=True)
    isVictim = BooleanField()


class Device(BaseSqliteModel):
    aci = ForeignKeyField(User, backref="devices")
    deviceId = IntegerField()
    pni = CharField(null=True)
    unidentifiedAccessKey = CharField()
    aciIdenKey = CharField()
    pniIdenKey = CharField()

    class Meta:
        primary_key = CompositeKey("aci", "deviceId")


def custom_dumps_bundle_spk(obj) -> str:
    validate(instance=obj, schema=db_json_schemas.key_schema_signed)
    return json.dumps(obj)


def custom_dumps_bundle_pre_keys(obj) -> str:
    validate(instance=obj, schema=db_json_schemas.prekey_bundle_schema)
    return json.dumps(obj)


def custom_dumps_bundle_kyber_keys(obj) -> str:
    validate(instance=obj, schema=db_json_schemas.kyber_keys_schema)
    return json.dumps(obj)


def custom_last_resort_kyber(obj) -> str:
    validate(instance=obj, schema=db_json_schemas.last_resort_kyber)
    return json.dumps(obj)


class LegitBundle(BaseSqliteModel):
    type = CharField()
    aci = ForeignKeyField(Device, field="aci", backref="legitbundles")
    deviceId = ForeignKeyField(Device, field="deviceId", backref="legitbundles")
    IdenKey = ForeignKeyField(Device, field="aciIdenKey", backref="legitbundles")
    SignedPreKey = JSONField(json_dumps=custom_dumps_bundle_spk)
    PreKeys = JSONField(json_dumps=custom_dumps_bundle_pre_keys)
    kyberKeys = JSONField(json_dumps=custom_dumps_bundle_kyber_keys)
    lastResortKyber = JSONField(json_dumps=custom_last_resort_kyber)

    class Meta:
        primary_key = CompositeKey("type", "aci", "deviceId")

    @classmethod
    def get_pre_key(
        cls, aci: str, device_id: int, key_id: int
    ) -> Union[dict, list[dict], None]:
        try:
            # Fetch the bundle using the primary key
            bundle = cls.get(cls.aci == aci, cls.deviceId == device_id)
            matching_keys = [
                key for key in bundle.PreKeys if key.get("keyId") == key_id
            ]

            if len(matching_keys) < 2:
                if len(matching_keys) == 1:
                    return matching_keys[0]  # one key
                return None
            logging.info(
                f"query get_kyber_key_by_aci with (aci={aci}, keyId={key_id}) has more than 1 result! "
            )
            return matching_keys
        except DoesNotExist:
            return None

    @classmethod
    def get_kyber_key(
        cls, aci: str, device_id: int, key_id: int
    ) -> Union[dict, list[dict], None]:
        try:
            # Fetch the bundle using the primary key
            bundle = cls.get(cls.aci == aci, cls.deviceId == device_id)
            matching_keys = [
                key for key in bundle.kyberKeys if key.get("keyId") == key_id
            ]

            if len(matching_keys) < 2:
                if len(matching_keys) == 1:
                    return matching_keys[0]  # one key
                return None
            logging.info(
                f"query get_kyber_key_by_aci with (aci={aci}, keyId={key_id}) has more than 1 result! "
            )
            return matching_keys
        except DoesNotExist:
            return None


def custom_dumps_signed(obj) -> str:
    validate(instance=obj, schema=Fake_key_schema_signed)
    return json.dumps(obj)


def custom_dumps_key(obj) -> str:
    validate(instance=obj, schema=Fake_key_schema)
    return json.dumps(obj)


def custom_dumps_signed_array(obj) -> str:
    validate(instance=obj, schema=Fake_key_array_schema_signed)
    return json.dumps(obj)


def custom_dumps_array(obj) -> str:
    validate(instance=obj, schema=Fake_key_array_schema)
    return json.dumps(obj)


class MitMBundle(BaseSqliteModel):
    type = CharField()
    aci = ForeignKeyField(Device, field="aci", backref="mitmbundles")
    deviceId = ForeignKeyField(Device, field="deviceId", backref="mitmbundles")
    FakeIdenKey = JSONField()
    FakeSignedPreKey = JSONField(json_dumps=custom_dumps_signed)
    FakePrekeys = JSONField(json_dumps=custom_dumps_array)
    fakeKyberKeys = JSONField(json_dumps=custom_dumps_signed_array)
    fakeLastResortKyber = JSONField(json_dumps=custom_dumps_key)

    class Meta:
        primary_key = CompositeKey("type", "aci", "deviceId")

    @classmethod
    def get_identity_keypair(cls, key_type: str, aci: str, device_id: int=1, with_private: bool=True)-> Union[dict, list[dict], None]:
        try:
            # Fetch the bundle using the primary key
            bundle = cls.get(cls.type==key_type, cls.aci == aci, cls.deviceId == device_id)
            # matching_keys = bundle.FakeIdenKey
            keys = bundle.FakeIdenKey

            if with_private:
                return keys
            else:
                return {k:v for k,v in keys.items() if k != "privateKey"}

        except DoesNotExist:
            return None

    @classmethod
    def get_pre_key(
        cls, aci: str, device_id: int, key_id: int, with_private=True
    ) -> Union[dict, list[dict], None]:
        try:
            # Fetch the bundle using the primary key
            bundle = cls.get(cls.aci == aci, cls.deviceId == device_id)
            matching_keys = [
                key for key in bundle.FakePrekeys if key.get("keyId") == key_id
            ]

            if not with_private:
                matching_keys = [
                    {k: v for k, v in d.items() if k != "privateKey"}
                    for d in matching_keys
                ]

            if len(matching_keys) < 2:
                if len(matching_keys) == 1:
                    return matching_keys[0]  # one key
                return None
            logging.info(
                f"query get_kyber_key_by_aci with (aci={aci}, keyId={key_id}) has more than 1 result! "
            )
            return matching_keys
        except DoesNotExist:
            return None

    @classmethod
    def get_kyber_key(
        cls, aci: str, device_id: int, key_id: int, with_private=True
    ) -> Union[dict, list[dict], None]:
        try:
            # Fetch the bundle using the primary key
            bundle = cls.get(cls.aci == aci, cls.deviceId == device_id)
            matching_keys = [
                key for key in bundle.fakeKyberKeys if key.get("keyId") == key_id
            ]

            if not with_private:
                matching_keys = [
                    {k: v for k, v in d.items() if k != "privateKey"}
                    for d in matching_keys
                ]

            if len(matching_keys) < 2:
                if len(matching_keys) == 1:
                    return matching_keys[0]  # one key
                return None
            logging.info(
                f"query get_kyber_key_by_aci with (aci={aci}, keyId={key_id}) has more than 1 result! "
            )
            return matching_keys
        except DoesNotExist:
            return None


class Session(BaseSqliteModel):
    aci1 = ForeignKeyField(Device, field="aci", backref="sessions")
    devId1 = ForeignKeyField(Device, field="deviceId", backref="sessions")
    aci2 = ForeignKeyField(Device, field="aci", backref="sessions")
    devId2 = ForeignKeyField(Device, field="deviceId", backref="sessions")
    sessionId = IntegerField()
    isVictimStarter = BooleanField()

    class Meta:
        primary_key = CompositeKey("aci1", "devId1", "aci2", "devId2")


class Messages(BaseSqliteModel):
    aci1 = ForeignKeyField(Device, field="aci", backref="messages")
    devId1 = ForeignKeyField(Device, field="deviceId", backref="messages")
    aci2 = ForeignKeyField(Device, field="aci", backref="messages")
    devId2 = ForeignKeyField(Device, field="deviceId", backref="messages")
    message = CharField()
    timestamp = TimestampField()
    counter = IntegerField()

    class Meta:
        primary_key = CompositeKey("aci1", "devId1", "aci2", "devId2", "counter")


def create_tables():
    with database:
        # database.create_tables([User, Device, LegitBundle])
        database.create_tables(
            [User, Device, LegitBundle, MitMBundle, Session, Messages]
        )
