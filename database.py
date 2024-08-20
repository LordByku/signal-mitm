import json
from jsonschema import validate, ValidationError

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


class LegitBundle(BaseSqliteModel):
    type = CharField()
    aci = ForeignKeyField(Device, field="aci", backref="legitbundles")
    device_id = ForeignKeyField(Device, field="device_id", backref="legitbundles")
    iden_key = ForeignKeyField(Device, field="aci_iden_key", backref="legitbundles")
    signed_pre_key = CharField()
    pre_keys = CharField()
    kyber_keys = CharField()
    last_resort_kyber = CharField()

    class Meta:
        primary_key = CompositeKey("type", "aci", "device_id")


key_schema_signed = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "keyId": {"type": "integer"},
        "publicKey": {"type": "string"},
        "signature": {"type": "string"},
        "privateKey": {"type": "string"}
    },
    "required": ["keyId", "publicKey", "signature", "privateKey"]
}

key_array_schema_signed = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "array",
    "items": [
        {
            "type": "object",
            "properties": {
                "keyId": {"type": "integer"},
                "publicKey": {"type": "string"},
                "signature": {"type": "string"},
                "privateKey": {"type": "string"}
            },
            "required": ["keyId", "publicKey", "signature", "privateKey"]
        }
    ]
}

key_array_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "array",
    "items": [
        {
            "type": "object",
            "properties": {
                "keyId": {"type": "integer"},
                "publicKey": {"type": "string"},
                "privateKey": {"type": "string"}
            },
            "required": ["keyId", "publicKey", "privateKey"]
        }
    ]
}

key_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "keyId": {"type": "integer"},
        "publicKey": {"type": "string"},
        "privateKey": {"type": "string"}
    },
    "required": ["keyId", "publicKey", "privateKey"]
}


def custom_dumps_signed(obj) -> str:
    validate(instance=obj, schema=key_schema_signed)
    return json.dumps(obj)


def custom_dumps_key(obj) -> str:
    validate(instance=obj, schema=key_schema)
    return json.dumps(obj)

def custom_dumps_signed_array(obj) -> str:
    validate(instance=obj, schema=key_array_schema_signed)
    return json.dumps(obj)

def custom_dumps_array(obj) -> str:
    validate(instance=obj, schema=key_array_schema)
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