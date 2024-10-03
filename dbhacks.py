import base64
import time
from typing import Annotated, Any, Optional, Type, Union

from pydantic import GetCoreSchemaHandler, PlainSerializer, PlainValidator
from pydantic_core import CoreSchema, core_schema
from signal_protocol.curve import KeyPair, PrivateKey, PublicKey
from signal_protocol.identity_key import IdentityKey, IdentityKeyPair
from signal_protocol.kem import KeyPair as KemKeyPair
from signal_protocol.kem import PublicKey as KemPublicKey
from signal_protocol.state import (
    KyberPreKeyRecord,
    PreKeyId,
    PreKeyRecord,
    SessionRecord,
    SignedPreKeyId,
    SignedPreKeyRecord,
)
from sqlalchemy import Dialect, String
from sqlalchemy.types import JSON, TypeDecorator
from sqlmodel import SQLModel

from protos.gen.storage_pb2 import SignedPreKeyRecordStructure

from sqlmodel._compat import SQLModelConfig  # noqa

"""
"Pydantic has Base64 types however they use encodestring and decodestring internally which add a `\\n` at the end :c"
"""
Base64Bytes = Annotated[
    bytes,
    PlainValidator(lambda x: base64.b64decode(x)),
    PlainSerializer(lambda x: base64.b64encode(x), when_used="json"),
]

Base64Bytes.__doc__ = (
    "Pydantic has Base64 types however they use encodestring and decodestring internally which add"
    "a `\\n` at the end :c"
)


class SQLModelValidation(SQLModel):
    """
    Helper class to allow for validation in SQLModel classes with table=True

    Normally SQLModel will skip Pydantic validation on assignment and let SQLAlchemy deal with any issues that might arise
    c.f. https://github.com/fastapi/sqlmodel/issues/52#issuecomment-2308359649
    """

    model_config = SQLModelConfig(  # noqa: the inheritance chain makes it work
        from_attributes=True, validate_assignment=True
    )


class _KeyRecord:
    key_id: int
    public_key: Union[PublicKey, KemPublicKey]
    signature: Optional[str]

    def __init__(
        self,
        key_id: int,
        public_key: Union[PublicKey, KemPublicKey],
        signature: Optional[str],
        # private_key: Optional[Union[PublicKey, KemPublicKey]]
    ):
        super().__init__()  # useless
        self.key_id = key_id
        self.public_key = public_key
        self.signature = signature

    def serialize(self) -> dict:
        data = dict()
        data["keyId"] = self.key_id
        data["publicKey"] = self.public_key.to_base64()
        if self.signature:
            data["signature"] = self.signature
        return data


class _IdentityKeyAnnotation(TypeDecorator):
    impl = String

    def process_bind_param(self, value: IdentityKey, dialect: Dialect) -> Optional[str]:
        if value is not None:
            value = value.to_base64()  # Assuming value is bytes
        return value

    def process_result_value(self, value: str, dialect: Dialect) -> Optional[IdentityKey]:
        if value is not None:
            value = IdentityKey.from_base64(value.encode())  # Assuming Base64Str.b64decode() returns bytes
        return value

    """
    https://docs.pydantic.dev/2.9/concepts/types/#handling-third-party-types
    """

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema:
        """
        We return a pydantic_core.CoreSchema that behaves in the following ways:

        TODO: document me :c
        """

        def validate_from_str(value: str) -> IdentityKey:
            # IdentityKey
            result = IdentityKey.from_base64(value.encode())
            return result

        from_str_schema = core_schema.chain_schema(
            [
                core_schema.str_schema(),
                core_schema.no_info_plain_validator_function(validate_from_str),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(IdentityKey),
                    from_str_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda instance: instance.to_base64()),
        )


class _IdentityKeyPairAnnotation(TypeDecorator):
    impl = JSON

    def process_bind_param(self, value: IdentityKeyPair, dialect: Dialect) -> dict:
        if value is not None:
            value = self.to_dict(value)  # Assuming value is bytes
        return value

    def process_result_value(self, value: dict, dialect: Dialect) -> IdentityKeyPair:
        if value is not None:
            value = self.validate_from_dict(value)
        return value

    @staticmethod
    def to_dict(value: IdentityKeyPair) -> dict:
        return {
            "publicKey": value.public_key().to_base64(),
            "privateKey": value.private_key().to_base64(),
        }

    @staticmethod
    def validate_from_dict(value: dict) -> IdentityKeyPair:
        return IdentityKeyPair(
            IdentityKey.from_base64(value.get("publicKey").encode()),
            PrivateKey.from_base64(value.get("privateKey").encode()),
        )

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema:
        """
        We return a pydantic_core.CoreSchema that behaves in the following ways:

        TODO: document me :c
        """

        from_dict_schema = core_schema.chain_schema(
            [
                core_schema.dict_schema(),
                core_schema.no_info_plain_validator_function(_IdentityKeyPairAnnotation.validate_from_dict),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_dict_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(IdentityKeyPair),
                    from_dict_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda instance: _IdentityKeyPairAnnotation.to_dict(instance)
            ),
        )


class _SignedECKeyAnnotation(TypeDecorator):
    impl = JSON

    def process_bind_param(self, value: _KeyRecord, dialect: Dialect):
        if value is not None:
            if isinstance(value, list):
                value = list(map(lambda x: x.serialize(), value))
            else:
                value = value.serialize()  # Assuming value is bytes
        return value

    def process_result_value(self, value: dict, dialect: Dialect):
        if value is not None:
            if isinstance(value, list):
                value = list(map(lambda x: self.validate_from_dict(x), value))
            else:
                value = self.validate_from_dict(value)
        return value

    @staticmethod
    def validate_from_dict(value: dict) -> _KeyRecord:
        return _KeyRecord(
            value.get("keyId"), PublicKey.from_base64(value.get("publicKey").encode()), value.get("signature")
        )

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema:
        from_dict_schema = core_schema.chain_schema(
            [
                core_schema.dict_schema(),
                core_schema.no_info_plain_validator_function(cls.validate_from_dict),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_dict_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(SignedPreKeyRecord),  # todo: look at this
                    from_dict_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda instance: instance.serialize()),
        )


class _SignedECKeyPairAnnotation(TypeDecorator):
    impl = JSON

    def process_bind_param(self, value: SignedPreKeyRecord, dialect: Dialect) -> dict:
        if value is not None:
            value = self.to_dict(value)  # Assuming value is bytes
        return value

    def process_result_value(self, value: dict, dialect: Dialect) -> SignedPreKeyRecord:
        if value is not None:
            value = self.validate_from_dict(value)
        return value

    @staticmethod
    def validate_from_dict(value: dict) -> SignedPreKeyRecord:
        key = KeyPair(
            PublicKey.from_base64(value.get("publicKey").encode()),
            PrivateKey.from_base64(value.get("privateKey").encode()),
        )
        record = SignedPreKeyRecord(
            SignedPreKeyId(value.get("keyId")),
            int(time.time()),
            key,
            base64.b64decode(value.get("signature")),
        )
        return record

    @staticmethod
    def to_dict(value: SignedPreKeyRecord) -> dict:
        return {
            "keyId": value.id().get_id(),
            "publicKey": value.public_key().to_base64(),
            "privateKey": value.private_key().to_base64(),
            "signature": base64.b64encode(value.signature()).decode(),
        }

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema:
        from_dict_schema = core_schema.chain_schema(
            [
                core_schema.dict_schema(),
                core_schema.no_info_plain_validator_function(cls.validate_from_dict),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_dict_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(SignedPreKeyRecord),  # todo: look at this
                    from_dict_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda instance: cls.to_dict(instance)),
        )


class _PreKeyPair(TypeDecorator):
    impl = JSON

    def process_bind_param(self, value: PreKeyRecord, dialect: Dialect) -> dict:
        if value is not None:
            if isinstance(value, list):
                value = list(map(lambda x: self.to_dict(x), value))
            else:
                value = self.to_dict(value)
        return value

    def process_result_value(self, value: dict, dialect: Dialect) -> PreKeyRecord:
        if value is not None:
            if isinstance(value, list):
                value = list(map(lambda x: self.validate_from_dict(x), value))
            else:
                value = self.validate_from_dict(value)
        return value

    @staticmethod
    def validate_from_dict(value: dict) -> PreKeyRecord:
        key = KeyPair(
            PublicKey.from_base64(value.get("publicKey").encode()),
            PrivateKey.from_base64(value.get("privateKey").encode()),
        )
        record = PreKeyRecord(
            PreKeyId(value.get("keyId")),
            key,
        )
        return record

    @staticmethod
    def to_dict(value: PreKeyRecord) -> dict:
        return {
            "keyId": value.id().get_id(),
            "publicKey": value.public_key().to_base64(),
            "privateKey": value.private_key().to_base64(),
        }

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema:
        from_dict_schema = core_schema.chain_schema(
            [
                core_schema.dict_schema(),
                core_schema.no_info_plain_validator_function(cls.validate_from_dict),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_dict_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(PreKeyRecord),  # todo: look at this
                    from_dict_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda instance: cls.to_dict(instance)),
        )


class _SignedKyberKeyAnnotation(_SignedECKeyAnnotation):
    @staticmethod
    def validate_from_dict(value: dict) -> _KeyRecord:
        return _KeyRecord(
            value.get("keyId"),
            KemPublicKey.from_base64(value.get("publicKey").encode()),
            value.get("signature"),
        )


def make_kyber_record(key_id: int, ts: int, kp: KemKeyPair, signature: bytes) -> KyberPreKeyRecord:
    sss = SignedPreKeyRecordStructure()
    sss.id = key_id
    sss.public_key = kp.get_public().serialize()
    sss.private_key = kp.get_private().serialize()
    sss.signature = signature
    sss.timestamp = ts
    return KyberPreKeyRecord.deserialize(sss.SerializeToString())


class _SignedKyberKeyPairAnnotation(TypeDecorator):
    impl = JSON

    def process_bind_param(self, value: KyberPreKeyRecord, dialect: Dialect) -> dict:
        if value is not None:
            if isinstance(value, list):
                value = list(map(lambda x: self.to_dict(x), value))
            else:
                value = self.to_dict(value)
        return value

    def process_result_value(self, value: dict, dialect: Dialect) -> KyberPreKeyRecord:
        if value is not None:
            if isinstance(value, list):
                value = list(map(lambda x: self.validate_from_dict(x), value))
            else:
                value = self.validate_from_dict(value)
        return value

    @staticmethod
    def validate_from_dict(value: dict) -> KyberPreKeyRecord:
        key = KemKeyPair.from_public_and_private(
            base64.b64decode(value.get("publicKey")), base64.b64decode(value.get("privateKey"))
        )
        record = make_kyber_record(
            value.get("keyId"),
            int(time.time()),
            key,
            base64.b64decode(value.get("signature")),
        )

        return record

    @staticmethod
    def to_dict(value: KyberPreKeyRecord) -> dict:
        return {
            "keyId": value.id().get_id(),
            "publicKey": value.public_key().to_base64(),
            "privateKey": value.secret_key().to_base64(),
            "signature": base64.b64encode(value.signature()).decode(),
        }

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema:
        from_dict_schema = core_schema.chain_schema(
            [
                core_schema.dict_schema(),
                core_schema.no_info_plain_validator_function(cls.validate_from_dict),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_dict_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(KyberPreKeyRecord),  # todo: look at this
                    from_dict_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda instance: cls.to_dict(instance)),
        )


class _SessionRecord(TypeDecorator):
    impl = String

    def process_bind_param(self, value: SessionRecord, dialect: Dialect) -> Optional[str]:
        if value is not None:
            value = value.to_base64()  # Assuming value is bytes
        return value

    def process_result_value(self, value: str, dialect) -> Optional[SessionRecord]:
        if value is not None:
            value = SessionRecord.from_base64(value.encode())
        return value

    """
    https://docs.pydantic.dev/2.9/concepts/types/#handling-third-party-types
    """

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema:
        """
        We return a pydantic_core.CoreSchema that behaves in the following ways:

        TODO: document me :c
        """

        def validate_from_str(value: str) -> SessionRecord:
            # IdentityKey
            result = SessionRecord.from_base64(value.encode())
            return result

        from_str_schema = core_schema.chain_schema(
            [
                core_schema.str_schema(),
                core_schema.no_info_plain_validator_function(validate_from_str),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(SessionRecord),
                    from_str_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda instance: instance.to_base64()),
        )


PydanticIdentityKey = Annotated[IdentityKey, _IdentityKeyAnnotation]
PydanticIdentityKeyPair = Annotated[IdentityKeyPair, _IdentityKeyPairAnnotation]

PydanticSignedPreKey = Annotated[_KeyRecord, _SignedECKeyAnnotation]
PydanticSignedPreKeyPair = Annotated[SignedPreKeyRecord, _SignedECKeyPairAnnotation]

PydanticPreKey = Annotated[_KeyRecord, _SignedECKeyAnnotation]
PydanticPreKeyPair = Annotated[_KeyRecord, _PreKeyPair]

PydanticPqKey = Annotated[_KeyRecord, _SignedKyberKeyAnnotation]
PydanticPqKeyPair = Annotated[KyberPreKeyRecord, _SignedKyberKeyPairAnnotation]

PydanticSessionRecord = Annotated[SessionRecord, _SessionRecord]
""" TODO: also add redundant forms
https://github.com/microsoft/pylance-release/issues/2574#issuecomment-1100808934

further reading
    https://www.gauge.sh/blog/the-trouble-with-all &
    https://www.apptension.com/blog-posts/tracing-the-evolution-of-pythons-typing-features
"""
__all__ = [
    "SQLModelValidation",
    "PydanticIdentityKey",
    "PydanticIdentityKeyPair",
    "PydanticSignedPreKey",
    "PydanticSignedPreKeyPair",
    "PydanticPreKey",
    "PydanticPreKeyPair",
    "PydanticPqKey",
    "PydanticPqKeyPair",
    "PydanticSessionRecord",
]
