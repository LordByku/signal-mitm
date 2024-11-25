from signal_protocol.curve import PublicKey
# Extracted from the clients (so far no certificate revocation has happened on PROD, but staging might be more flaky)
TRUST_ROOT_STAGING = b"BbqY1DzohE4NUZoVF+L18oUPrK3kILllLEJh2UnPSsEx"
TRUST_ROOT_PROD = b"BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF"

TRUST_ROOT_STAGING_PK = PublicKey.from_base64(TRUST_ROOT_STAGING)
TRUST_ROOT_PROD_PK = PublicKey.from_base64(TRUST_ROOT_PROD)

## Constants for the Signal Protocol

PRIMARY_DEVICE_ID = 1