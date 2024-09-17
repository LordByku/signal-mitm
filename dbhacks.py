import base64
from typing import Annotated, Any, Union, Optional, Type

from pydantic import (
    PlainSerializer,
    PlainValidator,
)
from signal_protocol.curve import PublicKey
from signal_protocol.identity_key import IdentityKey
from signal_protocol.kem import PublicKey as KemPublicKey
from sqlmodel import SQLModel
from sqlmodel._compat import SQLModelConfig  # noqa

#
"""
"Pydantic has Base64 types however they use encodestring and decodestring internally which add a `\\n` at the end :c"
"""
Base64Bytes = Annotated[
    bytes,
    PlainValidator(lambda x: base64.b64decode(x)),
    PlainSerializer(lambda x: base64.b64encode(x), when_used="json"),
]

Base64Bytes.__doc__ = "Pydantic has Base64 types however they use encodestring and decodestring internally which add a `\\n` at the end :c"


class SQLModelValidation(SQLModel):
    """
    Helper class to allow for validation in SQLModel classes with table=True

    Normally SQLModel will skip Pydantic validation on assignment and let SQLAlchemy deal with any issues that might arise
    c.f. https://github.com/fastapi/sqlmodel/issues/52#issuecomment-2308359649
    """

    model_config = SQLModelConfig(  # noqa: the inheritance chain makes it work
        from_attributes=True, validate_assignment=True
    )


from pydantic_core import CoreSchema, core_schema
from pydantic import GetCoreSchemaHandler


class PubKeyRecord:
    key_id: int
    public_key: Union[PublicKey, KemPublicKey]
    signature: Optional[str]

    def __init__(
            self,
            key_id: int,
            public_key: Union[PublicKey, KemPublicKey],
            signature: Optional[str],
    ):
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


class _IdentityKeyAnnotation:
    """
    https://docs.pydantic.dev/2.9/concepts/types/#handling-third-party-types
    """

    @classmethod
    def __get_pydantic_core_schema__(
            cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler
    ) -> CoreSchema:
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
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda instance: instance.to_base64()
            ),
        )


class _SignedPreKeyAnnotation:
    @staticmethod
    def validate_from_dict(value: dict) -> PubKeyRecord:
        return PubKeyRecord(
            value.get("keyId"),
            PublicKey.from_base64(value.get("publicKey").encode()),
            value.get("signature"),
        )

    @classmethod
    def __get_pydantic_core_schema__(
            cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler
    ) -> CoreSchema:
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
                    # core_schema.is_instance_schema(),
                    from_dict_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda instance: instance.serialize()
            ),
        )


class _SignedKyberKeyAnnotation(_SignedPreKeyAnnotation):
    @staticmethod
    def validate_from_dict(value: dict) -> PubKeyRecord:
        return PubKeyRecord(
            value.get("keyId"),
            KemPublicKey.from_base64(value.get("publicKey").encode()),
            value.get("signature"),
        )


PydanticIdentityKey = Annotated[IdentityKey, _IdentityKeyAnnotation]

PydanticSignedPreKey = Annotated[PubKeyRecord, _SignedPreKeyAnnotation]

PydanticPreKey = Annotated[PubKeyRecord, _SignedPreKeyAnnotation]

PydanticPqKey = Annotated[PubKeyRecord, _SignedKyberKeyAnnotation]

""" TODO: also add redundant forms 
https://github.com/microsoft/pylance-release/issues/2574#issuecomment-1100808934

further reading https://www.gauge.sh/blog/the-trouble-with-all & https://www.apptension.com/blog-posts/tracing-the-evolution-of-pythons-typing-features
"""
__all__ = [
    "SQLModelValidation",
    "PydanticIdentityKey",
    "PydanticSignedPreKey",
    "PydanticPreKey",
    "PydanticPqKey",
]
