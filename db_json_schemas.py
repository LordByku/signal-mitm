key_schema_signed = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "keyId": {"type": "integer"},
        "publicKey": {"type": "string"},
        "signature": {"type": "string"},
    },
    "required": ["keyId", "publicKey", "signature"],
}

prekey_bundle_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "array",
    "items": [
        {
            "type": "object",
            "properties": {
                "keyId": {"type": "integer"},
                "publicKey": {"type": "string"},
            },
            "required": ["keyId", "publicKey"],
        }
    ],
}

kyber_keys_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "array",
    "items": [
        {
            "type": "object",
            "properties": {
                "keyId": {"type": "integer"},
                "publicKey": {"type": "string"},
                "signature": {"type": "string"},
            },
            "required": ["keyId", "publicKey", "signature"],
        }
    ],
}

last_resort_kyber = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "keyId": {"type": "integer"},
        "publicKey": {"type": "string"},
        "signature": {"type": "string"},
    },
    "required": ["keyId", "publicKey", "signature"],
}

Fake_key_schema_signed = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "keyId": {"type": "integer"},
        "publicKey": {"type": "string"},
        "signature": {"type": "string"},
        "privateKey": {"type": "string"},
    },
    "required": ["keyId", "publicKey", "signature", "privateKey"],
}

Fake_key_array_schema_signed = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "array",
    "items": [
        {
            "type": "object",
            "properties": {
                "keyId": {"type": "integer"},
                "publicKey": {"type": "string"},
                "signature": {"type": "string"},
                "privateKey": {"type": "string"},
            },
            "required": ["keyId", "publicKey", "signature", "privateKey"],
        }
    ],
}

Fake_key_array_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "array",
    "items": [
        {
            "type": "object",
            "properties": {
                "keyId": {"type": "integer"},
                "publicKey": {"type": "string"},
                "privateKey": {"type": "string"},
            },
            "required": ["keyId", "publicKey", "privateKey"],
        }
    ],
}

Fake_key_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "keyId": {"type": "integer"},
        "publicKey": {"type": "string"},
        "privateKey": {"type": "string"},
    },
    "required": ["keyId", "publicKey", "privateKey"],
}
