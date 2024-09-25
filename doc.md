from sqlalchemy.orm.util import identity_key

# Database Module

`database` module (name pending) is designed to make it easy to manage database sessions and cryptographic material from `signal-protocol.py`. Here, you'll find an overview of the module's design, its core components, and usage guidelines.

## Overview

This module combines the powerful ORM capabilities of SQLAlchemy with Pydantic's data validation, all wrapped up in `SQLModel`. 

It includes components for _session management_ and database schema definitions, abstracting the work with cryptographic operations.

---

## Design Rationale

### Why SQLModel?

`SQLModel` is awesome because it brings together:
- **SQLAlchemy's ORM:** For powerful database interactions.
- **Pydantic's Validation:** For automatic data validation, parsing and serialization to external services (e.g. JSON).

This combo makes it easy to handle complex data types and ensures your data is in the right format.

### Custom Type Decorators and Type Aliases

To manage cryptographic material (like identity keys and signed pre-keys), we use custom SQLAlchemy type decorators and Pydantic type aliases. These make sure your cryptographic objects are stored and retrieved correctly from the database without you having to worry about serialization and deserialization.

Key custom types include:
- `_IdentityKeyAnnotation`
- `_IdentityKeyPairAnnotation`
- `_SignedECKeyAnnotation`
- `_SignedECKeyPairAnnotation`
- `_PreKeyPair`
- `_SignedKyberKeyAnnotation`
- `_SignedKyberKeyPairAnnotation`

## Modules

### Session Management (`session.py`)

The `DatabaseSessionManager` takes care of managing database sessions using the Singleton design pattern. This means only one instance will handle all database interactions, preventing any issues with multiple connections.

todo: currently it is not async aware (but that should be fine for our use-case)
#### Usage Example:

```python3
from session import DatabaseSessionManager

if __name__ == "__main__":
    s1 = DatabaseSessionManager()
    s2 = DatabaseSessionManager()
    if id(s1) == id(s2):
        print("Same")
    else:
        print("Different")
```


### Custom Type Decorators (`dbhacks.py`)
This module provides custom SQLAlchemy type decorators and Pydantic type aliases to handle cryptographic objects.

It exposes annotated Pydantic types that can be used to define the database model, while at the same time, act as the native Rust type. 

For example, a `SQLModel` `Data` with a field `key: PydanticIdentityKeyPair` can perform `signal_protocol.identity_key.IdentityKeyPair` operations so:

`data.key.private_key().calculate_signature(msg_bytes)` is a valid operation assuming `data` is an instance of `Data`.


#### Defining a custom type (advanced)

To define a custom type for a python class `PyClaass` one has to specify:
- the schema for `Pydantic`
  - this implies overriding the `__get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema` classmethod
- the process for binding an instance of `PyClass` to/from the database driver:
  - `process_bind_param(self, value, dialect):` controls how values are saved to the db; the `dialect` parameter tells you which engine is currently used (which can influences how the object has to bound to the SQL prepared statement -- e.g. some databases do not support a `JSON` type so you'd need to store it a string type)
  - `process_result_value(self, value, dialect):` handles the reserve direction, from a

#### Example of defining an IdentityKey

reminder: `IdentityKey` holds the public key material

```python3
from typing import Annotated, Optional, Type, Any
from signal_protocol.identity_key import IdentityKey

from pydantic_core import CoreSchema, core_schema
from pydantic import GetCoreSchemaHandler

from sqlalchemy import String, Dialect
from sqlalchemy.types import TypeDecorator

class _IdentityKeyAnnotation(TypeDecorator):
    impl = String

    def process_bind_param(self, value: IdentityKey, dialect: Dialect) -> Optional[str]:
        if value is not None:
            value = value.to_base64()
        return value

    def process_result_value(self, value: str, dialect: Dialect) -> Optional[IdentityKey]:
        if value is not None:
            value = IdentityKey.from_base64(value.encode())
        return value

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Type[Any], _handler: GetCoreSchemaHandler) -> CoreSchema:
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
                    core_schema.is_instance_schema(IdentityKey),
                    from_str_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda instance: instance.to_base64()),
        )

# Usage in a database model
PydanticIdentityKey = Annotated[IdentityKey, _IdentityKeyAnnotation]
```

More info (todo link docs):
- https://docs.pydantic.dev/2.9/concepts/types/#handling-third-party-types

### Database Schema Definitions (`database.py`)
This is where the database schema is defined using SQLModel. 

## Usage Guide

### Setting Up the Database
Before you do anything, create the database tables:

```python3
from database import create_tables
create_tables()
```

### Managing Database Sessions
Use the `DatabaseSessionManager` to handle your database sessions effortlessly:

```python3
from session import DatabaseSessionManager

with DatabaseSessionManager().get_session() as session:
    # Perform database operations within this context
    ...
```

### Handling Cryptographic Keys

Store and retrieve cryptographic keys using our custom type decorators:


```python3
from database import MitmBundle
from session import DatabaseSessionManager

from signal_protocol.identity_key import IdentityKeyPair
# Example: Inserting a new MitM bundle and retrieving it
with DatabaseSessionManager().get_session() as session:
    identity_key_pair = IdentityKeyPair.generate()
    new_entry = MitmBundle(type="aci", aci="exampleAci", device_id=1, fake_identity_key_pair=identity_key_pair)
    session.merge(new_entry)
    session.commit()

    result = MitmBundle.get_identity_keypair(session, "aci", "exampleAci", 1)
    print(f"Query Result (identity keypair): {result}")
```

todo: models currently do not autofill missing fields, that is a next feature (c.f my PayPal for faster support).

## tl;dr

This database module combines the best of SQLAlchemy and Pydantic using SQLModel. It makes handling database sessions and cryptographic keys a breeze, ensuring your data is always in the right format and securely stored. 

Happy coding!
