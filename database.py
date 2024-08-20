# import subprocess
# import os
# import sys
# import signal
# from itertools import product
# import sqlite3
# from pathlib import Path
import json
from jsonschema import validate, ValidationError

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
    aci = ForeignKeyField(User, backref='devices')
    deviceId = IntegerField()
    pni = CharField(null=True)
    unidentifiedAccessKey = CharField()
    aciIdenKey = CharField()
    pniIdenKey = CharField()

    class Meta:
        primary_key = CompositeKey('aci', 'deviceId')


class LegitBundle(BaseSqliteModel):
    type = CharField()
    aci = ForeignKeyField(Device, field="aci", backref='legitbundles')
    deviceId = ForeignKeyField(Device, field="deviceId", backref='legitbundles')
    IdenKey = ForeignKeyField(Device, field="aciIdenKey", backref='legitbundles')
    SignedPreKey = JSONField()
    PreKeys = JSONField()
    kyberKeys = JSONField()
    lastResortKyber = JSONField()

    class Meta:
        primary_key = CompositeKey('type', 'aci', 'deviceId')


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
    aci = ForeignKeyField(Device, field="aci", backref='mitmbundles')
    deviceId = ForeignKeyField(Device, field="deviceId", backref='mitmbundles')
    FakeIdenKey = JSONField()
    FakeSignedPreKey = JSONField(json_dumps=custom_dumps_signed)
    FakePrekeys = JSONField(json_dumps=custom_dumps_array)
    fakeKyberKeys = JSONField(json_dumps=custom_dumps_signed_array)
    fakeLastResortKyber = JSONField(json_dumps=custom_dumps_key)

    class Meta:
        primary_key = CompositeKey('type', 'aci', 'deviceId')


class Session(BaseSqliteModel):
    aci1 = ForeignKeyField(Device, field="aci", backref='sessions')
    devId1 = ForeignKeyField(Device, field="deviceId", backref='sessions')
    aci2 = ForeignKeyField(Device, field="aci", backref='sessions')
    devId2 = ForeignKeyField(Device, field="deviceId", backref='sessions')
    sessionId = IntegerField()
    isVictimStarter = BooleanField()

    class Meta:
        primary_key = CompositeKey('aci1', 'devId1', 'aci2', 'devId2')


class Messages(BaseSqliteModel):
    aci1 = ForeignKeyField(Device, field="aci", backref='messages')
    devId1 = ForeignKeyField(Device, field="deviceId", backref='messages')
    aci2 = ForeignKeyField(Device, field="aci", backref='messages')
    devId2 = ForeignKeyField(Device, field="deviceId", backref='messages')
    message = CharField()
    timestamp = TimestampField()
    counter = IntegerField()

    class Meta:
        primary_key = CompositeKey('aci1', 'devId1', 'aci2', 'devId2', 'counter')


def create_tables():
    with database:
        # database.create_tables([User, Device, LegitBundle])
        database.create_tables([User, Device, LegitBundle, MitMBundle, Session, Messages])
