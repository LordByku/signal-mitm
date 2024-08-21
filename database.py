import json
import logging
from typing import Union

import peewee
from jsonschema import (
    validate,
    ValidationError,
)  # todo: Handle ValidationError properly
import db_json_schemas
from db_json_schemas import (
    Fake_key_schema,
    Fake_key_array_schema,
    Fake_key_schema_signed,
    Fake_key_array_schema_signed,
)
from peewee import (
    Model,
    CharField,
    BooleanField,
    ForeignKeyField,
    CompositeKey,
    IntegerField,
    TimestampField,
)
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
    p_number = CharField(null=True)
    aci = CharField(null=True, primary_key=True)
    pni = CharField(null=True)
    is_victim = BooleanField()


class Device(BaseSqliteModel):
    aci = ForeignKeyField(User, backref="devices")
    device_id = IntegerField()
    pni = CharField(null=True)
    unidentified_access_key = CharField()
    aci_iden_key = CharField()
    pni_iden_key = CharField()

    class Meta:
        primary_key = CompositeKey("aci", "device_id")

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
    device_id = ForeignKeyField(Device, field="device_id", backref="legitbundles")
    iden_key = ForeignKeyField(Device, field="aci_iden_key", backref="legitbundles")
    signed_pre_key = JSONField(json_dumps=custom_dumps_bundle_spk)
    pre_keys = JSONField(json_dumps=custom_dumps_bundle_pre_keys)
    kyber_keys = JSONField(json_dumps=custom_dumps_bundle_kyber_keys)
    last_resort_kyber = JSONField(json_dumps=custom_last_resort_kyber)

    class Meta:
        primary_key = CompositeKey("type", "aci", "device_id")
        primary_key = CompositeKey("type", "aci", "deviceId")

    @classmethod
    def get_pre_key(
        cls, aci: str, device_id: int, key_id: int
    ) -> Union[dict, list[dict], None]:
        try:
            # Fetch the bundle using the primary key
            bundle = cls.get(cls.aci == aci, cls.device_id == device_id)
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
        except peewee.DoesNotExist:
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
        except peewee.DoesNotExist:
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
    device_id = ForeignKeyField(Device, field="device_id", backref="mitmbundles")
    fake_iden_key = JSONField()
    fake_signed_pre_key = JSONField(json_dumps=custom_dumps_signed)
    fake_pre_keys = JSONField(json_dumps=custom_dumps_array)
    fake_kyber_keys = JSONField(json_dumps=custom_dumps_signed_array)
    fake_last_resort_kyber = JSONField(json_dumps=custom_dumps_key)

    class Meta:
        primary_key = CompositeKey("type", "aci", "device_id")
        primary_key = CompositeKey("type", "aci", "deviceId")

    @classmethod
    def get_pre_key(
        cls, aci: str, device_id: int, key_id: int, with_private=True
    ) -> Union[dict, list[dict], None]:
        try:
            # Fetch the bundle using the primary key
            bundle = cls.get(cls.aci == aci, cls.device_id == device_id)
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
        except peewee.DoesNotExist:
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
        except peewee.DoesNotExist:
            return None


class Session(BaseSqliteModel):
    aci1 = ForeignKeyField(Device, field="aci", backref="sessions")
    dev_id1 = ForeignKeyField(Device, field="device_id", backref="sessions")
    aci2 = ForeignKeyField(Device, field="aci", backref="sessions")
    dev_id2 = ForeignKeyField(Device, field="device_id", backref="sessions")
    session_id = IntegerField()
    is_victim_starter = BooleanField()

    class Meta:
        primary_key = CompositeKey("aci1", "dev_id1", "aci2", "dev_id2")


class Messages(BaseSqliteModel):
    aci1 = ForeignKeyField(Device, field="aci", backref="messages")
    dev_id1 = ForeignKeyField(Device, field="device_id", backref="messages")
    aci2 = ForeignKeyField(Device, field="aci", backref="messages")
    dev_id2 = ForeignKeyField(Device, field="device_id", backref="messages")
    message = CharField()
    timestamp = TimestampField()
    counter = IntegerField()

    class Meta:
        primary_key = CompositeKey("aci1", "dev_id1", "aci2", "dev_id2", "counter")


def create_tables():
    with database:
        # database.create_tables([User, Device, LegitBundle])
        database.create_tables(
            [User, Device, LegitBundle, MitMBundle, Session, Messages]
        )
