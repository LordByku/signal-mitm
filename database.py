import time
from typing import List, Optional, Union, Dict, get_args

from datetime import datetime, timezone
import json
import base64

from sqlmodel import (
    Field,
    SQLModel,
    Relationship,
    JSON,
    create_engine,
    Session,
    select,
    String,
)
from pydantic import (
    BaseModel,
    ValidationError,
    validator,
    field_validator,
    Base64Str,
    PlainSerializer,
    PlainValidator,
)
from sqlalchemy import PrimaryKeyConstraint, Column
from sqlalchemy.exc import NoResultFound
from dbhacks import (
    SQLModelValidation,
    PydanticIdentityKey,
    PydanticSignedPreKey,
    PydanticPreKey,
    PydanticPqKey,
    PydanticIdentityKeyPair,
)
from session import DatabaseSessionManager

# IdentityKeyB = Annotated[
#     IdentityKey,
#     PlainValidator(lambda x: IdentityKey.from_base64(x)),
#     PlainSerializer(lambda x: x.to_base64(), when_used='json')
# ]
# IdentityKey library placeholder

# Database setup (engine creation is similar to the provided example):
sqlite_file_name = "mitm.db"
sqlite_url = f"sqlite:///./{sqlite_file_name}"
engine = create_engine(sqlite_url, echo=True)


# Models:
class User(SQLModel, table=True):
    aci: str = Field(default=None, primary_key=True)
    pni: Optional[str] = Field(default=None)
    e164: Optional[str] = Field(default=None)
    is_victim: bool
    devices: List["Device"] = Relationship(back_populates="user")


class Device(SQLModel, table=True):
    aci: str = Field(foreign_key="user.aci")
    device_id: int = Field(default=1)
    pni: Optional[str] = Field(default=None)
    unidentified_access_key: str
    aci_identity_key: str
    pni_identity_key: str

    user: User = Relationship(back_populates="devices")

    # composite primary keys are not directly supported by SQLModel so relying on the internal
    # SQLAlchemy support instead
    __table_args__ = (PrimaryKeyConstraint("aci", "device_id"),)


## REFACTOR: instead of holding all the possible bundles together as one row, it might make sense to split them into distinct rows with one key each
## for each possible bundle a user might expect. We have to first check how the server generates bundles
class LegitBundle(SQLModel, table=True):
    type: str = Field(
        primary_key=True, default="aci"
    )  # type is not present on the wire (bundle itself), but exists as a query-param
    aci: str = Field(foreign_key="device.aci", primary_key=True)
    device_id: int = Field(
        foreign_key="device.device_id",
        primary_key=True,
        default=1,
        alias="deviceId",
        schema_extra={"serialization_alias": "deviceId"},
    )
    registration_id: int = Field(
        alias="registrationId",
        schema_extra={
            "serialization_alias": "registrationId",
            "validation_alias": "registrationId",
        },
    )  # implies each device has its own (likely distinct) registration id
    identity_key: PydanticIdentityKey = Field(
        sa_column=Column(
            get_args(PydanticIdentityKey)[1],
            # foreign_key="device.aci_identity_key" # throws some warning... we'll deal with it when we get there
        ),
        alias="identityKey",
        schema_extra={
            "serialization_alias": "identityKey",
            "validation_alias": "identityKey",
        },
    )
    signed_pre_key: Optional[PydanticSignedPreKey] = Field(
        sa_column=Column(get_args(PydanticSignedPreKey)[1]),
        alias="signedPreKey",
        schema_extra={
            "serialization_alias": "signedPreKey",
            "validation_alias": "signedPreKey",
        },
    )
    # pre_key: Optional[dict] = Field(sa_column=Column(JSON), alias="preKey",
    #                                 schema_extra={"serialization_alias": "preKey", "validation_alias": "preKey"})
    pre_key: Optional[list[PydanticPreKey]] = Field(
        sa_column=Column(get_args(PydanticPreKey)[1]),
        alias="preKey",
        schema_extra={"serialization_alias": "preKey", "validation_alias": "preKey"},
    )

    # kyber_key: Optional[dict] = Field(sa_column=Column(JSON), alias="pqPreKey",
    #                                   schema_extra={"serialization_alias": "pqPreKey", "validation_alias": "pqPreKey"})
    kyber_key: Optional[list[PydanticPqKey]] = Field(
        sa_column=Column(get_args(PydanticPqKey)[1]),
        alias="pqPreKey",
        schema_extra={
            "serialization_alias": "pqPreKey",
            "validation_alias": "pqPreKey",
        },
    )

    # last_resort_kyber: Optional[dict] = Field(sa_column=Column(JSON), alias="lastResortKyber", schema_extra={"serialization_alias": "lastResortKyber"}) # not put on the wire?

    # composite primary keys are not directly supported by SQLModel so relying on the internal
    # SQLAlchemy support instead
    __table_args__ = (PrimaryKeyConstraint("type", "aci", "device_id"),)

    # # Custom validation or dumping can be handled with Pydantic models
    # @validator('SignedPreKey', 'PreKeys', 'kyberKeys', 'lastResortKyber', pre=True)
    # def validate_json_fields(cls, v):
    #     # Custom validation logic and conversion to string if needed
    #     # Use corresponding Pydantic models for each JSON field
    #     if v:
    #         # Here, replace SignedPreKey etc. with actual validation
    #         # This is a placeholder for the concept
    #         # json.dumps can be replaced with the specific model's parsing logic
    #         return json.loads(json.dumps(v))
    #     return v


class MitmBundle(SQLModelValidation, table=True):
    type: str = Field(primary_key=True)
    aci: str = Field(foreign_key="device.aci", primary_key=True)
    device_id: int = Field(
        foreign_key="device.device_id",
        primary_key=True,
        default=1,
        alias="deviceId",
        schema_extra={
            "serialization_alias": "deviceId",
            "validation_alias": "deviceId",
        },
    )
    fake_identity_key_pair: Optional[PydanticIdentityKeyPair] = Field(
        sa_column=Column(get_args(PydanticIdentityKeyPair)[1]),
        alias="identityKey",
        schema_extra={
            "serialization_alias": "identityKey",
            "validation_alias": "identityKey",
        },
    )
    fake_signed_pre_key: Optional[dict] = Field(
        sa_column=Column(JSON),
        alias="signedPreKey",
        schema_extra={
            "serialization_alias": "signedPreKey",
            "validation_alias": "signedPreKey",
        },
    )
    fake_pre_keys: Optional[list[dict]] = Field(
        sa_column=Column(JSON),
        alias="preKeys",
        schema_extra={"serialization_alias": "preKeys", "validation_alias": "preKeys"},
    )
    fake_kyber_keys: Optional[list[dict]] = Field(
        sa_column=Column(JSON),
        alias="kyberKeys",
        schema_extra={
            "serialization_alias": "pqPreKeys",
            "validation_alias": "pqPreKeys",
        },
    )
    fake_last_resort_kyber: Optional[dict] = Field(
        sa_column=Column(JSON),
        alias="lastResortKyber",
        schema_extra={
            "serialization_alias": "pqLastResortPreKey",
            "validation_alias": "pqLastResortPreKey",
        },
    )

    # composite primary keys are not directly supported by SQLModel so relying on the internal
    # SQLAlchemy support instead
    __table_args__ = (PrimaryKeyConstraint("type", "aci", "device_id"),)
    """ TODO: for fake bundles it makes sense to tie the creation of the database entry with the creation 
    of the keys. Instead of doing it at the level of `MitmUser`. This reduces the responsibility of the class.
    having only to reinstate from a Database entry.
    """

    @field_validator("type")  # noqa
    @classmethod
    def aci_or_pni(cls, value: str) -> str:
        if value not in ("aci", "pni"):
            raise ValueError("Type must be 'aci' or 'pni'")
        return value

    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)  # Initialize parent class
        # Set default values or initialize as needed
        self.fake_identity_key = kwargs.get('fake_identity_key', ...)
    """

    @classmethod
    def _get_key_pair(
        cls,
        _session: Session,
        key_type: str,
        aci: str,
        device_id: int,
        key_field: str,
        with_private: bool = True,
    ) -> Union[Dict[str, str], None]:
        try:
            stmt = select(cls).where(
                cls.type == key_type, cls.aci == aci, cls.device_id == device_id
            )
            bundle = _session.exec(
                stmt
            ).one()  # noqa: unexpected type here is a false warning, but I cannot typecase to suppess it

            key_data = getattr(bundle, key_field)
            if isinstance(key_data, dict) and not with_private:
                # If with_private is False, remove the 'privateKey' from the returned dict
                key_data.pop(
                    "privateKey", None
                )  # Safely attempting to remove privateKey if exists
            return key_data
        except NoResultFound:
            return None

    @classmethod
    def get_identity_keypair(
        cls,
        _session: Session,
        key_type: str,
        aci: str,
        device_id: int = 1,
        with_private: bool = True,
    ) -> Union[Dict[str, str], None]:
        return cls._get_key_pair(
            _session, key_type, aci, device_id, "fake_identity_key", with_private
        )

    @classmethod
    def get_signed_pre_key_pair(
        cls,
        _session: Session,
        key_type: str,
        aci: str,
        device_id: int = 1,
        with_private: bool = True,
    ) -> Union[Dict[str, str], None]:
        return cls._get_key_pair(
            _session, key_type, aci, device_id, "fake_signed_pre_key", with_private
        )

    @classmethod
    def get_last_resort_kyber_key_pair(
        cls,
        _session: Session,
        key_type: str,
        aci: str,
        device_id: int = 1,
        with_private: bool = True,
    ) -> Union[Dict[str, str], None]:
        return cls._get_key_pair(
            _session, key_type, aci, device_id, "fake_last_resort_kyber", with_private
        )

    @classmethod
    def _get_key_from_list(
        cls,
        _session: Session,
        key_type: str,
        aci: str,
        device_id: int,
        keys_attribute: str,
        key_id: Optional[int],
        with_private: bool,
    ) -> Optional[Dict[str, str]]:
        stmt = select(cls).where(
            cls.type == key_type, cls.aci == aci, cls.device_id == device_id
        )
        bundle = _session.exec(
            stmt
        ).one_or_none()  # noqa: unexpected type here is a false warning, but I cannot typecase to suppess it
        if bundle:
            keys = getattr(bundle, keys_attribute, [])
            for key in keys:
                if key.get("keyId") == key_id:
                    if not with_private:
                        return {k: v for k, v in key.items() if k != "privateKey"}
                    return key
        return None

    # Previous method refactored to use the generic _get_key_from_bundle
    @classmethod
    def get_fake_pre_key(
        cls,
        _session: Session,
        key_type: str,
        aci: str,
        device_id: int,
        key_id: int,
        with_private: bool = True,
    ) -> Optional[Dict[str, str]]:
        return cls._get_key_from_list(
            _session, key_type, aci, device_id, "fake_pre_keys", key_id, with_private
        )

    @classmethod
    def get_fake_kyber_key(
        cls,
        _session: Session,
        key_type: str,
        aci: str,
        device_id: int,
        key_id: int,
        with_private: bool = True,
    ) -> Optional[Dict[str, str]]:
        return cls._get_key_from_list(
            _session, key_type, aci, device_id, "fake_kyber_keys", key_id, with_private
        )


class Conversation(SQLModel, table=True):
    aci1: str = Field(
        default=None, foreign_key="device.aci"
    )  # Adjust based on the actual Device model's ID fields
    dev_id1: int = Field(default=None, foreign_key="device.device_id")
    aci2: str = Field(default=None, foreign_key="device.aci")
    dev_id2: int = Field(default=None, foreign_key="device.device_id")
    session_id: int
    initiated_by_victim: bool

    __table_args__ = (PrimaryKeyConstraint("aci1", "dev_id1", "aci2", "dev_id2"),)


class Messages(SQLModel, table=True):
    aci1: str = Field(default=None, foreign_key="device.aci")
    dev_id1: int = Field(default=None, foreign_key="device.device_id")
    aci2: str = Field(default=None, foreign_key="device.aci")
    dev_id2: int = Field(default=None, foreign_key="device.device_id")
    message: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )  # Use timezone-aware UTC now
    counter: int

    __table_args__ = (
        PrimaryKeyConstraint("aci1", "dev_id1", "aci2", "dev_id2", "counter"),
    )


def create_tables():
    SQLModel.metadata.create_all(engine)


import copy


def json_join_public(data1: list[dict], data2: dict):
    result = copy.deepcopy(data1)
    for item in result:
        key_id = str(item["keyId"])
        if key_id in data2:
            item["privateKey"] = data2[key_id]
    return result


# Example usage (ensuring your environment supports async operations):
if __name__ == "__main__":
    create_tables()
    """
    Test 1. Test db creation and some simple functions
    """
    #
    # # Insert a new entry into MitmBundle and query the fake_identity_key
    # with Session(engine) as session:
    #     new_entry = MitmBundle(
    #         type="aci",
    #         aci="exampleAci",
    #         device_id=1,
    #         fake_identity_key=(
    #             {"publicKey": "BQWQ7qfIsCJx4SrZLLZs2uCuevINGl+nvRQL9L5dCsE9",
    #              "privateKey": "sNOWsE2WvqdWM3W+lU2y6H4W03+QC/HV+k4mGqms/3E="},
    #         )[0],
    #         fake_signed_pre_key=(
    #             {"publicKey": "meep2",
    #              "privateKey": "meep.ag"},
    #         )[0],
    #         fake_pre_keys=[{"keyId": 2897358, "publicKey": "BagdqSzaz3tB17P3jiDwIzW0i4HomgBRJMnMgBUFw0B6",
    #                         "privateKey": "KNeCzhxPlqC2Y9G+dFrkwa5o10I2YB7HrtLurhQ6EXY="},
    #                        {"keyId": 2897359, "publicKey": "BV6ucpNdSlf6c3FxCcj1gA1x0P3HmGhkqltxcK8H5ONP",
    #                         "privateKey": "kL7xiaHS/daBvacd0154qeG3F5uiPPIf6scyWXVUxlY="}]
    #         # other fields as necessary
    #     )
    #     session.merge(new_entry)
    #     session.commit()
    #
    #     # Query the fake_identity_key for a specific entry
    #     result = MitmBundle.get_identity_keypair(session, "aci", "exampleAci", 1, with_private=False)
    #     print(f"Query Result: {result}")
    #     result = MitmBundle.get_identity_keypair(session, "aci", "exampleAci", 1)
    #     print(f"Query Result: {result}")
    #
    #     result = MitmBundle.get_signed_pre_key_pair(session, "aci", "exampleAci", 1)
    #     print(f"Query Result: {result}")
    #
    #     result = MitmBundle.get_fake_pre_key(session, "aci", "exampleAci", 1, 2897358, with_private=False)
    #     print(f"Query Result: {result}")
    #
    #     result = MitmBundle.get_fake_pre_key(session, "aci", "exampleAci", 1, 2897358)
    #     print(f"Query Result: {result}")
    #
    #     data = new_entry.model_dump_json(indent=2, by_alias=True)
    #     print(f"ENTRY v\n{data}")

    """
    Test 2: load a bundle and make it happy ^^
    """
    with open("tests/fixtures/bundle.json") as f:
        bundle = json.load(f)
        bundle["devices"][0]["identityKey"] = bundle["identityKey"]
        bundle = bundle["devices"][0]
        bundle["aci"] = "test1"
        bundle["type"] = "aci"
        bundle["preKey"] = [bundle["preKey"]]
        bundle["pqPreKey"] = [bundle["pqPreKey"]]
        # bundle["identityKey"]
        lb = LegitBundle.model_validate(bundle)
        print(lb)
        print(lb.model_dump_json(indent=2, by_alias=True))

        print(lb.identity_key)
        print(lb.signed_pre_key.public_key)

        with Session(engine) as ses:
            ses.merge(lb)
            ses.commit()

        del lb

        with Session(engine) as ses:
            print("FRESH FROM DB!")
            meep = ses.exec(select(LegitBundle)).first()
            print(meep)
            print(meep.model_dump_json(indent=4, by_alias=True))

    """
    Test 3: Fake Bundle(s)
    """
    from signal_protocol import helpers
    from signal_protocol.identity_key import IdentityKeyPair
    from signal_protocol.curve import KeyPair
    from signal_protocol.state import SignedPreKeyRecord, SignedPreKeyId

    identity_keypair = IdentityKeyPair.generate()
    spk = KeyPair.generate()
    spk_record = SignedPreKeyRecord(
        SignedPreKeyId(44),
        int(time.time()),
        spk,
        identity_keypair.private_key().calculate_signature(spk.public_key().serialize()),
    )
    fake_pre_keys, fake_secret_pre_keys = helpers.create_keys_data(
        1,
        identity_keypair,
        spk,
        # last_kyber
        prekey_start_at=76,
        kyber_prekey_start_at=55055
        # pq_pre_keys[0]["keyId"]
    )  ## spk is a string, wtf is the keyId?

    fake_pre_keys["preKeys"] = json_join_public(fake_pre_keys["preKeys"], fake_secret_pre_keys["preKeys"] )
    fake_pre_keys["pqPreKeys"] = json_join_public(fake_pre_keys["pqPreKeys"], fake_secret_pre_keys["pqPreKeys"] )
    fake_pre_keys["identityKey"] = {
        "publicKey": identity_keypair.public_key().to_base64(),
        "privateKey": identity_keypair.private_key().to_base64(),
    }
    fake_pre_keys["signedPreKey"] = {
        "publicKey": spk.public_key().to_base64(),
        "privateKey": spk.private_key().to_base64(),
        "keyId": spk_record.id().get_id()
    }
    # data = json_join_public(fake_pre_keys["pre]"], fake_secret_pre_keys)

    print(fake_pre_keys)
    fake_pre_keys["type"] = "aci"
    fake_pre_keys["aci"] = "bobs"
    mitmb = MitmBundle.model_validate(fake_pre_keys)
    print(mitmb)
    print(mitmb.model_dump_json(indent=2, by_alias=True))

    with DatabaseSessionManager().get_session() as session:
        session.merge(mitmb)
        session.commit()

    with DatabaseSessionManager().get_session() as session:
            print("FRESH FROM DB! (MitmBundle)")
            meep : MitmBundle = ses.exec(select(MitmBundle)).first()
            print(meep)
            print(meep.model_dump_json(indent=4, by_alias=True))
            print(meep.fake_identity_key_pair)