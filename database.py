# import subprocess
# import os
# import sys
# import signal
# from itertools import product
# import sqlite3
# from pathlib import Path
from  peewee import *

#TODO: Remove relationship of pni Device and pni User

DB_NAME = "mitm.db"

database = SqliteDatabase(DB_NAME)
database.connect()

class User(Model):
    pNumber=CharField(null=True)
    aci = CharField(null=True)
    pni = CharField(null=True)
    isVictim = BooleanField()

    class Meta:
        database = database
        primary_key = PrimaryKeyField('aci')

class Device(Model):
    aci = ForeignKeyField(User, backref='devices')
    deviceId = IntegerField()
    #pni = ForeignKeyField(User, backref='devices')
    pni = CharField(null=True)
    unidentifiedAccessKey = CharField()
    aciIdenKey = CharField()
    pniIdenKey = CharField()

    class Meta:
        primary_key = CompositeKey('aci', 'deviceId')

class LegitBundle(Model):
    type = CharField()
    aci = ForeignKeyField(Device, backref='legitbundles')
    deviceId = ForeignKeyField(Device, backref='legitbundles')
    aciSignedPreKey = CharField()
    aciPreKeys = CharField()
    kyberKeys = CharField()
    lastResortKyber = CharField()

    class Meta:
        primary_key = CompositeKey('aci', 'deviceId')

class MitMBundle(Model):
    type = CharField()
    aci = ForeignKeyField(Device, backref='mitmbundles')
    deviceId = ForeignKeyField(Device, backref='mitmbundles')
    aciFakeIdenKey = CharField()
    aciFakeSignedPreKey = CharField()
    aciFakePrekeys = CharField()
    fakeKyberKeys = CharField()
    lastResortKyber = CharField()

    class Meta:
        primary_key = CompositeKey('aci', 'deviceId')

class Session(Model):
    aci1 = ForeignKeyField(Device, backref='sessions')
    devId1 = ForeignKeyField(Device, backref='sessions')
    aci2 = ForeignKeyField(User, backref='sessions')
    devId2 = ForeignKeyField(Device, backref='sessions')
    sessionId = IntegerField()
    isVictimStarter = BooleanField()

    class Meta:
        primary_key = CompositeKey('aci', 'deviceId')

class Messages(Model):
    aci1 = ForeignKeyField(Device, backref='sessions')
    devId1 = ForeignKeyField(Device, backref='sessions')
    aci2 = ForeignKeyField(User, backref='sessions')
    devId2 = ForeignKeyField(Device, backref='sessions')
    message = CharField()
    timestamp = TimestampField()
    counter = IntegerField()

    class Meta:
        primary_key = CompositeKey('aci1', 'devId1', 'aci2', 'devId2', 'counter')