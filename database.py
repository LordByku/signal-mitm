from peewee import (
    SqliteDatabase,
    Model,
    CharField,
    BooleanField,
    ForeignKeyField,
    CompositeKey,
    IntegerField,
    TimestampField,
)

# TODO: Remove relationship of pni Device and pni User

DB_NAME = "mitm.db"

database = SqliteDatabase(DB_NAME)
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
        primary_key = CompositeKey("aci", "deviceId")


class LegitBundle(BaseSqliteModel):
    type = CharField()
    aci = ForeignKeyField(Device, field="aci", backref="legitbundles")
    device_id = ForeignKeyField(Device, field="deviceId", backref="legitbundles")
    iden_key = ForeignKeyField(Device, field="aciIdenKey", backref="legitbundles")
    signed_pre_key = CharField()
    pre_keys = CharField()
    kyber_keys = CharField()
    last_resort_kyber = CharField()

    class Meta:
        primary_key = CompositeKey("type", "aci", "deviceId")


class MitMBundle(BaseSqliteModel):
    type = CharField()
    aci = ForeignKeyField(Device, field="aci", backref="mitmbundles")
    deviceId = ForeignKeyField(Device, field="deviceId", backref="mitmbundles")
    fake_iden_key = CharField()
    fake_signed_pre_key = CharField()
    fake_pre_keys = CharField()
    fake_kyber_keys = CharField()
    fake_last_resort_kyber = CharField()

    class Meta:
        primary_key = CompositeKey("type", "aci", "deviceId")


class Session(BaseSqliteModel):
    aci1 = ForeignKeyField(Device, field="aci", backref="sessions")
    dev_id1 = ForeignKeyField(Device, field="deviceId", backref="sessions")
    aci2 = ForeignKeyField(Device, field="aci", backref="sessions")
    dev_id2 = ForeignKeyField(Device, field="deviceId", backref="sessions")
    session_id = IntegerField()
    is_victim_starter = BooleanField()

    class Meta:
        primary_key = CompositeKey("aci1", "devId1", "aci2", "devId2")


class Messages(BaseSqliteModel):
    aci1 = ForeignKeyField(Device, field="aci", backref="messages")
    dev_id1 = ForeignKeyField(Device, field="deviceId", backref="messages")
    aci2 = ForeignKeyField(Device, field="aci", backref="messages")
    dev_id2 = ForeignKeyField(Device, field="deviceId", backref="messages")
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
