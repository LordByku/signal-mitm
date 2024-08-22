from mitmproxy.http import HTTPFlow
from xepor import InterceptedAPI, RouteType

SIGNAL_PRODUCTION_SERVER = "chat.signal.org"
SIGNAL_STAGING_SERVER = "chat.staging.signal.org"
HOST_HTTPBIN = SIGNAL_STAGING_SERVER

api = InterceptedAPI(HOST_HTTPBIN)


@api.route("/v1/accounts/account/{identifier}", rtype=RouteType.REQUEST)
def req_v1_accounts_account_identifier(flow: HTTPFlow, identifier):
    """
            Check whether an account exists
            Enforced unauthenticated endpoint. Checks whether an account with a given identifier exists.

         Parameters:
            identifier  (required)
              location: path
              An ACI or PNI account identifier to check


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/account/{identifier}", rtype=RouteType.RESPONSE)
def resp_v1_accounts_account_identifier(flow: HTTPFlow, identifier):
    """
            Check whether an account exists
            Enforced unauthenticated endpoint. Checks whether an account with a given identifier exists.

         Responses:
            200 - An account with the given identifier was found.
            400 - Request must not be authenticated.
            404 - An account was not found for the given identifier.
            422 - Invalid request format.
            429 - Rate-limited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_hash/confirm", rtype=RouteType.REQUEST)
def req_v1_accounts_username_hash_confirm(flow: HTTPFlow):
    """
            Confirm username hash
            Authenticated endpoint. For a previously reserved username hash, confirm that this username hash is now taken
    by this account.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_hash/confirm", rtype=RouteType.RESPONSE)
def resp_v1_accounts_username_hash_confirm(flow: HTTPFlow):
    """
            Confirm username hash
            Authenticated endpoint. For a previously reserved username hash, confirm that this username hash is now taken
    by this account.

         Responses:
            200 - Username hash confirmed successfully.
            401 - Account authentication check failed.
            409 - Given username hash doesn't match the reserved one or no reservation found.
            410 - Username hash not available (username can't be used).
            422 - Invalid request format.
            429 - Ratelimited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/me", rtype=RouteType.REQUEST)
def req_v1_accounts_me(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/me", rtype=RouteType.RESPONSE)
def resp_v1_accounts_me(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/me", rtype=RouteType.REQUEST)
def req_v1_accounts_me(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/me", rtype=RouteType.RESPONSE)
def resp_v1_accounts_me(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/apn", rtype=RouteType.REQUEST)
def req_v1_accounts_apn(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/apn", rtype=RouteType.RESPONSE)
def resp_v1_accounts_apn(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/apn", rtype=RouteType.REQUEST)
def req_v1_accounts_apn(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/apn", rtype=RouteType.RESPONSE)
def resp_v1_accounts_apn(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/gcm", rtype=RouteType.REQUEST)
def req_v1_accounts_gcm(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/gcm", rtype=RouteType.RESPONSE)
def resp_v1_accounts_gcm(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/gcm", rtype=RouteType.REQUEST)
def req_v1_accounts_gcm(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/gcm", rtype=RouteType.RESPONSE)
def resp_v1_accounts_gcm(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_hash", rtype=RouteType.REQUEST)
def req_v1_accounts_username_hash(flow: HTTPFlow):
    """
            Delete username hash
            Authenticated endpoint. Deletes previously stored username for the account.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_hash", rtype=RouteType.RESPONSE)
def resp_v1_accounts_username_hash(flow: HTTPFlow):
    """
            Delete username hash
            Authenticated endpoint. Deletes previously stored username for the account.

         Responses:
            204 - Username successfully deleted.
            401 - Account authentication check failed.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_link", rtype=RouteType.REQUEST)
def req_v1_accounts_username_link(flow: HTTPFlow):
    """
            Set username link
            Authenticated endpoint. For the given encrypted username generates a username link handle.
    The username link handle can be used to lookup the encrypted username.
    An account can only have one username link at a time; this endpoint overwrites the previous encrypted username if there was one.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_link", rtype=RouteType.RESPONSE)
def resp_v1_accounts_username_link(flow: HTTPFlow):
    """
            Set username link
            Authenticated endpoint. For the given encrypted username generates a username link handle.
    The username link handle can be used to lookup the encrypted username.
    An account can only have one username link at a time; this endpoint overwrites the previous encrypted username if there was one.

         Responses:
            200 - Username Link updated successfully.
            401 - Account authentication check failed.
            409 - Username is not set for the account.
            422 - Invalid request format.
            429 - Ratelimited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_link", rtype=RouteType.REQUEST)
def req_v1_accounts_username_link(flow: HTTPFlow):
    """
            Delete username link
            Authenticated endpoint. Deletes username link for the given account: previously store encrypted username is deleted
    and username link handle is deactivated.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_link", rtype=RouteType.RESPONSE)
def resp_v1_accounts_username_link(flow: HTTPFlow):
    """
            Delete username link
            Authenticated endpoint. Deletes username link for the given account: previously store encrypted username is deleted
    and username link handle is deactivated.

         Responses:
            204 - Username Link successfully deleted.
            401 - Account authentication check failed.
            429 - Ratelimited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/turn", rtype=RouteType.REQUEST)
def req_v1_accounts_turn(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/turn", rtype=RouteType.RESPONSE)
def resp_v1_accounts_turn(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_hash/{usernameHash}", rtype=RouteType.REQUEST)
def req_v1_accounts_username_hash_usernameHash(flow: HTTPFlow, usernameHash):
    """
            Lookup username hash
            Forced unauthenticated endpoint. For the given username hash, look up a user ID.

         Parameters:
            usernameHash  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_hash/{usernameHash}", rtype=RouteType.RESPONSE)
def resp_v1_accounts_username_hash_usernameHash(flow: HTTPFlow, usernameHash):
    """
            Lookup username hash
            Forced unauthenticated endpoint. For the given username hash, look up a user ID.

         Responses:
            200 - Account found for the given username.
            400 - Request must not be authenticated.
            404 - Account not found for the given username.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_link/{uuid}", rtype=RouteType.REQUEST)
def req_v1_accounts_username_link_uuid(flow: HTTPFlow, uuid):
    """
            Lookup username link
            Enforced unauthenticated endpoint. For the given username link handle, looks up the database for an associated encrypted username.
    If found, encrypted username is returned, otherwise responds with 404 Not Found.

         Parameters:
            uuid  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_link/{uuid}", rtype=RouteType.RESPONSE)
def resp_v1_accounts_username_link_uuid(flow: HTTPFlow, uuid):
    """
            Lookup username link
            Enforced unauthenticated endpoint. For the given username link handle, looks up the database for an associated encrypted username.
    If found, encrypted username is returned, otherwise responds with 404 Not Found.

         Responses:
            200 - Username link with the given handle was found.
            400 - Request must not be authenticated.
            404 - Username link was not found for the given handle.
            422 - Invalid request format.
            429 - Ratelimited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/registration_lock", rtype=RouteType.REQUEST)
def req_v1_accounts_registration_lock(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/registration_lock", rtype=RouteType.RESPONSE)
def resp_v1_accounts_registration_lock(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/registration_lock", rtype=RouteType.REQUEST)
def req_v1_accounts_registration_lock(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/registration_lock", rtype=RouteType.RESPONSE)
def resp_v1_accounts_registration_lock(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_hash/reserve", rtype=RouteType.REQUEST)
def req_v1_accounts_username_hash_reserve(flow: HTTPFlow):
    """
            Reserve username hash
            Authenticated endpoint. Takes in a list of hashes of potential username hashes, finds one that is not taken,
    and reserves it for the current account.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/username_hash/reserve", rtype=RouteType.RESPONSE)
def resp_v1_accounts_username_hash_reserve(flow: HTTPFlow):
    """
            Reserve username hash
            Authenticated endpoint. Takes in a list of hashes of potential username hashes, finds one that is not taken,
    and reserves it for the current account.

         Responses:
            200 - Username hash reserved successfully.
            401 - Account authentication check failed.
            409 - All username hashes from the list are taken.
            422 - Invalid request format.
            429 - Ratelimited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/attributes", rtype=RouteType.REQUEST)
def req_v1_accounts_attributes(flow: HTTPFlow):
    """


         Parameters:
            X-Signal-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/attributes", rtype=RouteType.RESPONSE)
def resp_v1_accounts_attributes(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/name", rtype=RouteType.REQUEST)
def req_v1_accounts_name(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/name", rtype=RouteType.RESPONSE)
def resp_v1_accounts_name(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/whoami", rtype=RouteType.REQUEST)
def req_v1_accounts_whoami(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/accounts/whoami", rtype=RouteType.RESPONSE)
def resp_v1_accounts_whoami(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/accounts/number", rtype=RouteType.REQUEST)
def req_v2_accounts_number(flow: HTTPFlow):
    """
            Change number
            Changes a phone number for an existing account.
         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/accounts/number", rtype=RouteType.RESPONSE)
def resp_v2_accounts_number(flow: HTTPFlow):
    """
            Change number
            Changes a phone number for an existing account.
         Responses:
            200 - The phone number associated with the authenticated account was changed successfully
            401 - Account authentication check failed.
            403 - Verification failed for the provided Registration Recovery Password
            409 - Mismatched number of devices or device ids in 'devices to notify' list
            410 - Mismatched registration ids in 'devices to notify' list
            422 - The request did not pass validation
            423 -
            429 - Too many attempts

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v2/accounts/phone_number_identity_key_distribution", rtype=RouteType.REQUEST
)
def req_v2_accounts_phone_number_identity_key_distribution(flow: HTTPFlow):
    """
            Set phone-number identity keys
            Updates key material for the phone-number identity for all devices and sends a synchronization message to companion devices
         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v2/accounts/phone_number_identity_key_distribution", rtype=RouteType.RESPONSE
)
def resp_v2_accounts_phone_number_identity_key_distribution(flow: HTTPFlow):
    """
            Set phone-number identity keys
            Updates key material for the phone-number identity for all devices and sends a synchronization message to companion devices
         Responses:
            200 - Indicates the transaction was successful and returns basic information about this account.
            401 - Account authentication check failed.
            403 - This endpoint can only be invoked from the account's primary device.
            422 - The request body failed validation.
            409 - The set of devices specified in the request does not match the set of devices active on the account.
            410 - The registration IDs provided for some devices do not match those stored on the server.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/accounts/data_report", rtype=RouteType.REQUEST)
def req_v2_accounts_data_report(flow: HTTPFlow):
    """
            Produces a report of non-ephemeral account data stored by the service

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/accounts/data_report", rtype=RouteType.RESPONSE)
def resp_v2_accounts_data_report(flow: HTTPFlow):
    """
            Produces a report of non-ephemeral account data stored by the service

         Responses:
            200 - Response with data report. A plain text representation is a field in the response.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/accounts/phone_number_discoverability", rtype=RouteType.REQUEST)
def req_v2_accounts_phone_number_discoverability(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/accounts/phone_number_discoverability", rtype=RouteType.RESPONSE)
def resp_v2_accounts_phone_number_discoverability(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/upload/form", rtype=RouteType.REQUEST)
def req_v1_archives_upload_form(flow: HTTPFlow):
    """
            Fetch message backup upload form
            Retrieve an upload form that can be used to perform a resumable upload of a message backup.
         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/upload/form", rtype=RouteType.RESPONSE)
def resp_v1_archives_upload_form(flow: HTTPFlow):
    """
            Fetch message backup upload form
            Retrieve an upload form that can be used to perform a resumable upload of a message backup.
         Responses:
            200 -
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives", rtype=RouteType.REQUEST)
def req_v1_archives(flow: HTTPFlow):
    """
            Fetch backup info
            Retrieve information about the currently stored backup
         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives", rtype=RouteType.RESPONSE)
def resp_v1_archives(flow: HTTPFlow):
    """
            Fetch backup info
            Retrieve information about the currently stored backup
         Responses:
            200 -
            404 - No existing backups found
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives", rtype=RouteType.REQUEST)
def req_v1_archives(flow: HTTPFlow):
    """
            Refresh backup
            Indicate that this backup is still active. Clients must periodically upload new backups or perform a refresh
    via a POST request. If a backup is not refreshed, after 30 days it may be deleted.

         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives", rtype=RouteType.RESPONSE)
def resp_v1_archives(flow: HTTPFlow):
    """
            Refresh backup
            Indicate that this backup is still active. Clients must periodically upload new backups or perform a refresh
    via a POST request. If a backup is not refreshed, after 30 days it may be deleted.

         Responses:
            204 - The backup was successfully refreshed
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives", rtype=RouteType.REQUEST)
def req_v1_archives(flow: HTTPFlow):
    """
            Delete entire backup
            Delete all backup metadata, objects, and stored public key. To use backups again, a public key must be resupplied.

         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives", rtype=RouteType.RESPONSE)
def resp_v1_archives(flow: HTTPFlow):
    """
            Delete entire backup
            Delete all backup metadata, objects, and stored public key. To use backups again, a public key must be resupplied.

         Responses:
            204 - The backup has been successfully removed
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media/batch", rtype=RouteType.REQUEST)
def req_v1_archives_media_batch(flow: HTTPFlow):
    """
            Batched backup media
            Copy and re-encrypt media from the attachments cdn into the backup cdn.

    The original already encrypted attachment will be encrypted with the provided key material before being copied

    If the batch request is processed at all, a 207 will be returned and the outcome of each constituent copy will
    be provided as a separate entry in the response.

         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media/batch", rtype=RouteType.RESPONSE)
def resp_v1_archives_media_batch(flow: HTTPFlow):
    """
            Batched backup media
            Copy and re-encrypt media from the attachments cdn into the backup cdn.

    The original already encrypted attachment will be encrypted with the provided key material before being copied

    If the batch request is processed at all, a 207 will be returned and the outcome of each constituent copy will
    be provided as a separate entry in the response.

         Responses:
            207 - The request was processed and each operation's outcome must be inspected individually. This does NOT necessarily
    indicate the operation was a success.

            413 - All media capacity has been consumed. Free some space to continue.
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media", rtype=RouteType.REQUEST)
def req_v1_archives_media(flow: HTTPFlow):
    """
            List media objects
            Retrieve a list of media objects stored for this backup-id. A client may have previously stored media objects
    that are no longer referenced in their current backup. To reclaim storage space used by these orphaned
    objects, perform a list operation and remove any unreferenced media objects via DELETE /v1/backups/<mediaId>.

         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64

            cursor
              location: query
              A cursor returned by a previous call

            limit
              location: query
              The number of entries to return per call


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media", rtype=RouteType.RESPONSE)
def resp_v1_archives_media(flow: HTTPFlow):
    """
            List media objects
            Retrieve a list of media objects stored for this backup-id. A client may have previously stored media objects
    that are no longer referenced in their current backup. To reclaim storage space used by these orphaned
    objects, perform a list operation and remove any unreferenced media objects via DELETE /v1/backups/<mediaId>.

         Responses:
            200 -
            400 - Bad arguments. The request may have been made on an authenticated channel
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media", rtype=RouteType.REQUEST)
def req_v1_archives_media(flow: HTTPFlow):
    """
            Backup media
            Copy and re-encrypt media from the attachments cdn into the backup cdn.

    The original, already encrypted, attachment will be encrypted with the provided key material before being copied.

    A particular destination media id should not be reused with a different source media id or different encryption
    parameters.

         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media", rtype=RouteType.RESPONSE)
def resp_v1_archives_media(flow: HTTPFlow):
    """
            Backup media
            Copy and re-encrypt media from the attachments cdn into the backup cdn.

    The original, already encrypted, attachment will be encrypted with the provided key material before being copied.

    A particular destination media id should not be reused with a different source media id or different encryption
    parameters.

         Responses:
            200 -
            400 - Bad arguments. The request may have been made on an authenticated channel
            413 - All media capacity has been consumed. Free some space to continue.
            410 - The source object was not found.
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media/delete", rtype=RouteType.REQUEST)
def req_v1_archives_media_delete(flow: HTTPFlow):
    """
            Delete media objects
            Delete media objects stored with this backup-id
         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media/delete", rtype=RouteType.RESPONSE)
def resp_v1_archives_media_delete(flow: HTTPFlow):
    """
            Delete media objects
            Delete media objects stored with this backup-id
         Responses:
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/auth", rtype=RouteType.REQUEST)
def req_v1_archives_auth(flow: HTTPFlow):
    """
            Fetch ZK credentials
            After setting a blinded backup-id with PUT /v1/archives/, this fetches credentials that can be used to perform
    operations against that backup-id. Clients may (and should) request up to 7 days of credentials at a time.

    The redemptionStart and redemptionEnd seconds must be UTC day aligned, and must not span more than 7 days.

    Each credential contains a receipt level which indicates the backup level the credential is good for. If the
    account has paid backup access that expires at some point in the provided redemption window, credentials with
    redemption times after the expiration may be on a lower backup level.

    Clients must validate the receipt level on the credential matches a known receipt level before using it.

         Parameters:
            redemptionStartSeconds  (required)
              location: query
              None

            redemptionEndSeconds  (required)
              location: query
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/auth", rtype=RouteType.RESPONSE)
def resp_v1_archives_auth(flow: HTTPFlow):
    """
            Fetch ZK credentials
            After setting a blinded backup-id with PUT /v1/archives/, this fetches credentials that can be used to perform
    operations against that backup-id. Clients may (and should) request up to 7 days of credentials at a time.

    The redemptionStart and redemptionEnd seconds must be UTC day aligned, and must not span more than 7 days.

    Each credential contains a receipt level which indicates the backup level the credential is good for. If the
    account has paid backup access that expires at some point in the provided redemption window, credentials with
    redemption times after the expiration may be on a lower backup level.

    Clients must validate the receipt level on the credential matches a known receipt level before using it.

         Responses:
            200 -
            400 - The start/end did not meet alignment/duration requirements
            404 - Could not find an existing blinded backup id
            429 - Rate limited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/auth/read", rtype=RouteType.REQUEST)
def req_v1_archives_auth_read(flow: HTTPFlow):
    """
            Get CDN read credentials
            Retrieve credentials used to read objects stored on the backup cdn
         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64

            cdn  (required)
              location: query
              The number of the CDN to get credentials for


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/auth/read", rtype=RouteType.RESPONSE)
def resp_v1_archives_auth_read(flow: HTTPFlow):
    """
            Get CDN read credentials
            Retrieve credentials used to read objects stored on the backup cdn
         Responses:
            200 -
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/redeem-receipt", rtype=RouteType.REQUEST)
def req_v1_archives_redeem_receipt(flow: HTTPFlow):
    """
            Redeem receipt
            Redeem a receipt acquired from /v1/subscription/{subscriberId}/receipt_credentials to mark the account as
    eligible for the paid backup tier.

    After successful redemption, subsequent requests to /v1/archive/auth will return credentials with the level on
    the provided receipt until the expiration time on the receipt.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/redeem-receipt", rtype=RouteType.RESPONSE)
def resp_v1_archives_redeem_receipt(flow: HTTPFlow):
    """
            Redeem receipt
            Redeem a receipt acquired from /v1/subscription/{subscriberId}/receipt_credentials to mark the account as
    eligible for the paid backup tier.

    After successful redemption, subsequent requests to /v1/archive/auth will return credentials with the level on
    the provided receipt until the expiration time on the receipt.

         Responses:
            204 - The receipt was redeemed
            400 - The provided presentation or receipt was invalid
            429 - Rate limited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/backupid", rtype=RouteType.REQUEST)
def req_v1_archives_backupid(flow: HTTPFlow):
    """
            Set backup id
            Set a (blinded) backup-id for the account. Each account may have a single active backup-id that can be used
    to store and retrieve backups. Once the backup-id is set, BackupAuthCredentials can be generated
    using /v1/archives/auth.

    The blinded backup-id and the key-pair used to blind it should be derived from a recoverable secret.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/backupid", rtype=RouteType.RESPONSE)
def resp_v1_archives_backupid(flow: HTTPFlow):
    """
            Set backup id
            Set a (blinded) backup-id for the account. Each account may have a single active backup-id that can be used
    to store and retrieve backups. Once the backup-id is set, BackupAuthCredentials can be generated
    using /v1/archives/auth.

    The blinded backup-id and the key-pair used to blind it should be derived from a recoverable secret.

         Responses:
            204 - The backup-id was set
            400 - The provided backup auth credential request was invalid
            429 - Rate limited. Too many attempts to change the backup-id have been made

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/keys", rtype=RouteType.REQUEST)
def req_v1_archives_keys(flow: HTTPFlow):
    """
            Set public key
            Permanently set the public key of an ED25519 key-pair for the backup-id. All requests that provide a anonymous
    BackupAuthCredentialPresentation (including this one!) must also sign the presentation with the private key
    corresponding to the provided public key.

         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/keys", rtype=RouteType.RESPONSE)
def resp_v1_archives_keys(flow: HTTPFlow):
    """
            Set public key
            Permanently set the public key of an ED25519 key-pair for the backup-id. All requests that provide a anonymous
    BackupAuthCredentialPresentation (including this one!) must also sign the presentation with the private key
    corresponding to the provided public key.

         Responses:
            204 - The public key was set
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media/upload/form", rtype=RouteType.REQUEST)
def req_v1_archives_media_upload_form(flow: HTTPFlow):
    """
            Fetch media attachment upload form
            Retrieve an upload form that can be used to perform a resumable upload of an attachment. After uploading, the
    attachment can be copied into the backup at PUT /archives/media/.

    Like the account authenticated version at /attachments, the uploaded object is only temporary.

         Parameters:
            X-Signal-ZK-Auth  (required)
              location: header
              Presentation of a ZK backup auth credential acquired from /v1/archives/auth, encoded in standard padded base64

            X-Signal-ZK-Auth-Signature  (required)
              location: header
              Signature of the ZK auth credential's presentation, encoded in standard padded base64


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/archives/media/upload/form", rtype=RouteType.RESPONSE)
def resp_v1_archives_media_upload_form(flow: HTTPFlow):
    """
            Fetch media attachment upload form
            Retrieve an upload form that can be used to perform a resumable upload of an attachment. After uploading, the
    attachment can be copied into the backup at PUT /archives/media/.

    Like the account authenticated version at /attachments, the uploaded object is only temporary.

         Responses:
            200 -
            429 - Rate limited.
            403 - Forbidden. The request had insufficient permissions to perform the requested action
            401 - The provided backup auth credential presentation could not be verified or
    The public key signature was invalid or
    There is no backup associated with the backup-id in the presentation
            400 - Bad arguments. The request may have been made on an authenticated channel

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/art/auth", rtype=RouteType.REQUEST)
def req_v1_art_auth(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/art/auth", rtype=RouteType.RESPONSE)
def resp_v1_art_auth(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/attachments/form/upload", rtype=RouteType.REQUEST)
def req_v2_attachments_form_upload(flow: HTTPFlow):
    """


         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/attachments/form/upload", rtype=RouteType.RESPONSE)
def resp_v2_attachments_form_upload(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v3/attachments/form/upload", rtype=RouteType.REQUEST)
def req_v3_attachments_form_upload(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v3/attachments/form/upload", rtype=RouteType.RESPONSE)
def resp_v3_attachments_form_upload(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v4/attachments/form/upload", rtype=RouteType.REQUEST)
def req_v4_attachments_form_upload(flow: HTTPFlow):
    """
            Get an upload form
            Retrieve an upload form that can be used to perform a resumable upload. The response will include a cdn number
    indicating what protocol should be used to perform the upload.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v4/attachments/form/upload", rtype=RouteType.RESPONSE)
def resp_v4_attachments_form_upload(flow: HTTPFlow):
    """
            Get an upload form
            Retrieve an upload form that can be used to perform a resumable upload. The response will include a cdn number
    indicating what protocol should be used to perform the upload.

         Responses:
            200 - Success, response body includes upload form
            413 - Too many attempts
            429 - Too many attempts

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/call-link/create-auth", rtype=RouteType.REQUEST)
def req_v1_call_link_create_auth(flow: HTTPFlow):
    """
            Generate a credential for creating call links
            Generate a credential over a truncated timestamp, room ID, and account UUID. With zero knowledge
    group infrastructure, the server does not know the room ID.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/call-link/create-auth", rtype=RouteType.RESPONSE)
def resp_v1_call_link_create_auth(flow: HTTPFlow):
    """
            Generate a credential for creating call links
            Generate a credential over a truncated timestamp, room ID, and account UUID. With zero knowledge
    group infrastructure, the server does not know the room ID.

         Responses:
            200 - `JSON` with generated credentials.
            400 - Invalid create call link credential request.
            401 - Account authentication check failed.
            422 - Invalid request format.
            429 - Ratelimited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/calling/relays", rtype=RouteType.REQUEST)
def req_v1_calling_relays(flow: HTTPFlow):
    """
            Get 1:1 calling relay options for the client
            Get 1:1 relay addresses in IpV4, Ipv6, and URL formats.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/calling/relays", rtype=RouteType.RESPONSE)
def resp_v1_calling_relays(flow: HTTPFlow):
    """
            Get 1:1 calling relay options for the client
            Get 1:1 relay addresses in IpV4, Ipv6, and URL formats.

         Responses:
            200 - `JSON` with call endpoints.
            400 - Invalid get call endpoint request.
            401 - Account authentication check failed.
            422 - Invalid request format.
            429 - Rate limited.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/certificate/delivery", rtype=RouteType.REQUEST)
def req_v1_certificate_delivery(flow: HTTPFlow):
    """


         Parameters:
            includeE164
              location: query
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/certificate/delivery", rtype=RouteType.RESPONSE)
def resp_v1_certificate_delivery(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/certificate/auth/group", rtype=RouteType.REQUEST)
def req_v1_certificate_auth_group(flow: HTTPFlow):
    """


         Parameters:
            redemptionStartSeconds
              location: query
              None

            redemptionEndSeconds
              location: query
              None

            zkcCredential
              location: query
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/certificate/auth/group", rtype=RouteType.RESPONSE)
def resp_v1_certificate_auth_group(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/challenge", rtype=RouteType.REQUEST)
def req_v1_challenge(flow: HTTPFlow):
    """
            Submit proof of a challenge completion
            Some server endpoints (the "send message" endpoint, for example) may return a 428 response indicating the client must complete a challenge before continuing.
    Clients may use this endpoint to provide proof of a completed challenge. If successful, the client may then
    continue their original operation.

         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/challenge", rtype=RouteType.RESPONSE)
def resp_v1_challenge(flow: HTTPFlow):
    """
            Submit proof of a challenge completion
            Some server endpoints (the "send message" endpoint, for example) may return a 428 response indicating the client must complete a challenge before continuing.
    Clients may use this endpoint to provide proof of a completed challenge. If successful, the client may then
    continue their original operation.

         Responses:
            200 - Indicates the challenge proof was accepted
            413 - Too many attempts
            429 - Too many attempts

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/challenge/push", rtype=RouteType.REQUEST)
def req_v1_challenge_push(flow: HTTPFlow):
    """
            Request a push challenge
            Clients may proactively request a push challenge by making an empty POST request. Push challenges will only be
    sent to the requesting account’s main device. When the push is received it may be provided as proof of completed
    challenge to /v1/challenge.
    APNs challenge payloads will be formatted as follows:
    ```
    {
        "aps": {
            "sound": "default",
            "alert": {
                "loc-key": "APN_Message"
            }
        },
        "rateLimitChallenge": "{CHALLENGE_TOKEN}"
    }
    ```
    FCM challenge payloads will be formatted as follows:
    ```
    {"rateLimitChallenge": "{CHALLENGE_TOKEN}"}
    ```

    Clients may retry the PUT in the event of an HTTP/5xx response (except HTTP/508) from the server, but must
    implement an exponential back-off system and limit the total number of retries.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/challenge/push", rtype=RouteType.RESPONSE)
def resp_v1_challenge_push(flow: HTTPFlow):
    """
            Request a push challenge
            Clients may proactively request a push challenge by making an empty POST request. Push challenges will only be
    sent to the requesting account’s main device. When the push is received it may be provided as proof of completed
    challenge to /v1/challenge.
    APNs challenge payloads will be formatted as follows:
    ```
    {
        "aps": {
            "sound": "default",
            "alert": {
                "loc-key": "APN_Message"
            }
        },
        "rateLimitChallenge": "{CHALLENGE_TOKEN}"
    }
    ```
    FCM challenge payloads will be formatted as follows:
    ```
    {"rateLimitChallenge": "{CHALLENGE_TOKEN}"}
    ```

    Clients may retry the PUT in the event of an HTTP/5xx response (except HTTP/508) from the server, but must
    implement an exponential back-off system and limit the total number of retries.

         Responses:
            200 - Indicates a payload to the account's primary device has been attempted. When clients receive a challenge push
    notification, they may issue a PUT request to /v1/challenge.

            404 - The server does not have a push notification token for the authenticated account’s main device; clients may add a push
    token and try again

            413 - Too many attempts
            429 - Too many attempts

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/provisioning/code", rtype=RouteType.REQUEST)
def req_v1_devices_provisioning_code(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/provisioning/code", rtype=RouteType.RESPONSE)
def resp_v1_devices_provisioning_code(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices", rtype=RouteType.REQUEST)
def req_v1_devices(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices", rtype=RouteType.RESPONSE)
def resp_v1_devices(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/link", rtype=RouteType.REQUEST)
def req_v1_devices_link(flow: HTTPFlow):
    """
       Link a device to an account
       Links a device to an account identified by a given phone number.

    Parameters:
       Authorization
         location: header
         None

       User-Agent
         location: header
         None



    """
    # Implement the function body here
    pass


@api.route("/v1/devices/link", rtype=RouteType.RESPONSE)
def resp_v1_devices_link(flow: HTTPFlow):
    """
       Link a device to an account
       Links a device to an account identified by a given phone number.

    Responses:
       200 - The new device was linked to the calling account
       403 - The given account was not found or the given verification code was incorrect
       409 - The new device is missing a capability supported by all other devices on the account
       411 - The given account already has its maximum number of linked devices
       422 - The request did not pass validation
       429 - Too many attempts


    """
    # Implement the function body here
    pass


@api.route("/v1/devices/{device_id}", rtype=RouteType.REQUEST)
def req_v1_devices_device_id(flow: HTTPFlow, device_id):
    """


         Parameters:
            device_id  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/{device_id}", rtype=RouteType.RESPONSE)
def resp_v1_devices_device_id(flow: HTTPFlow, device_id):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/capabilities", rtype=RouteType.REQUEST)
def req_v1_devices_capabilities(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/capabilities", rtype=RouteType.RESPONSE)
def resp_v1_devices_capabilities(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/public_key", rtype=RouteType.REQUEST)
def req_v1_devices_public_key(flow: HTTPFlow):
    """
            Sets a public key for authentication
            Sets the authentication public key for the authenticated device. The public key will be used for
    authentication in the nascent gRPC-over-Noise API. Existing devices must upload a public key before they can
    use the gRPC-over-Noise API, and this endpoint exists to facilitate migration to the new API.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/public_key", rtype=RouteType.RESPONSE)
def resp_v1_devices_public_key(flow: HTTPFlow):
    """
            Sets a public key for authentication
            Sets the authentication public key for the authenticated device. The public key will be used for
    authentication in the nascent gRPC-over-Noise API. Existing devices must upload a public key before they can
    use the gRPC-over-Noise API, and this endpoint exists to facilitate migration to the new API.

         Responses:
            200 - Public key stored successfully
            401 - Account authentication check failed
            422 - Invalid request format

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/unauthenticated_delivery", rtype=RouteType.REQUEST)
def req_v1_devices_unauthenticated_delivery(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/devices/unauthenticated_delivery", rtype=RouteType.RESPONSE)
def resp_v1_devices_unauthenticated_delivery(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/directory/auth", rtype=RouteType.REQUEST)
def req_v2_directory_auth(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/directory/auth", rtype=RouteType.RESPONSE)
def resp_v2_directory_auth(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/donation/redeem-receipt", rtype=RouteType.REQUEST)
def req_v1_donation_redeem_receipt(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/donation/redeem-receipt", rtype=RouteType.RESPONSE)
def resp_v1_donation_redeem_receipt(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/keepalive", rtype=RouteType.REQUEST)
def req_v1_keepalive(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/keepalive", rtype=RouteType.RESPONSE)
def resp_v1_keepalive(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/keepalive/provisioning", rtype=RouteType.REQUEST)
def req_v1_keepalive_provisioning(flow: HTTPFlow):
    """


    Parameters:



    """
    # Implement the function body here
    pass


@api.route("/v1/keepalive/provisioning", rtype=RouteType.RESPONSE)
def resp_v1_keepalive_provisioning(flow: HTTPFlow):
    """


    Responses:
       default - default response


    """
    # Implement the function body here
    pass


@api.route("/v1/key-transparency/monitor", rtype=RouteType.REQUEST)
def req_v1_key_transparency_monitor(flow: HTTPFlow):
    """
            Monitor the given search keys in the key transparency log
            Enforced unauthenticated endpoint. Return proofs proving that the log tree
    has been constructed correctly in later entries for each of the given search keys .

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/key-transparency/monitor", rtype=RouteType.RESPONSE)
def resp_v1_key_transparency_monitor(flow: HTTPFlow):
    """
            Monitor the given search keys in the key transparency log
            Enforced unauthenticated endpoint. Return proofs proving that the log tree
    has been constructed correctly in later entries for each of the given search keys .

         Responses:
            200 - All search keys exist in the log
            404 - At least one search key lookup did not find the key
            413 - Ratelimited
            422 - Invalid request format

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/key-transparency/search", rtype=RouteType.REQUEST)
def req_v1_key_transparency_search(flow: HTTPFlow):
    """
            Search for the given search keys in the key transparency log
            Enforced unauthenticated endpoint. Returns a response if all search keys exist in the key transparency log.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/key-transparency/search", rtype=RouteType.RESPONSE)
def resp_v1_key_transparency_search(flow: HTTPFlow):
    """
            Search for the given search keys in the key transparency log
            Enforced unauthenticated endpoint. Returns a response if all search keys exist in the key transparency log.

         Responses:
            200 - All search key lookups were successful
            403 - At least one search key lookup to value mapping was invalid
            404 - At least one search key lookup did not find the key
            413 - Ratelimited
            422 - Invalid request format

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/keys/check", rtype=RouteType.REQUEST)
def req_v2_keys_check(flow: HTTPFlow):
    """
            Check keys
            Checks that client and server have consistent views of repeated-use keys. For a given identity type, clients
    submit a digest of their repeated-use key material. The digest is calculated as:

    SHA256(identityKeyBytes || signedEcPreKeyId || signedEcPreKeyIdBytes || lastResortKeyId || lastResortKeyBytes)

    …where the elements of the hash are:

    - identityKeyBytes: the serialized form of the client's public identity key as produced by libsignal (i.e. one
      version byte followed by 32 bytes of key material for a total of 33 bytes)
    - signedEcPreKeyId: an 8-byte, big-endian representation of the ID of the client's signed EC pre-key
    - signedEcPreKeyBytes: the serialized form of the client's signed EC pre-key as produced by libsignal (i.e. one
      version byte followed by 32 bytes of key material for a total of 33 bytes)
    - lastResortKeyId: an 8-byte, big-endian representation of the ID of the client's last-resort Kyber key
    - lastResortKeyBytes: the serialized form of the client's last-resort Kyber key as produced by libsignal (i.e. one
      version byte followed by 1568 bytes of key material for a total of 1569 bytes)

         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/keys/check", rtype=RouteType.RESPONSE)
def resp_v2_keys_check(flow: HTTPFlow):
    """
            Check keys
            Checks that client and server have consistent views of repeated-use keys. For a given identity type, clients
    submit a digest of their repeated-use key material. The digest is calculated as:

    SHA256(identityKeyBytes || signedEcPreKeyId || signedEcPreKeyIdBytes || lastResortKeyId || lastResortKeyBytes)

    …where the elements of the hash are:

    - identityKeyBytes: the serialized form of the client's public identity key as produced by libsignal (i.e. one
      version byte followed by 32 bytes of key material for a total of 33 bytes)
    - signedEcPreKeyId: an 8-byte, big-endian representation of the ID of the client's signed EC pre-key
    - signedEcPreKeyBytes: the serialized form of the client's signed EC pre-key as produced by libsignal (i.e. one
      version byte followed by 32 bytes of key material for a total of 33 bytes)
    - lastResortKeyId: an 8-byte, big-endian representation of the ID of the client's last-resort Kyber key
    - lastResortKeyBytes: the serialized form of the client's last-resort Kyber key as produced by libsignal (i.e. one
      version byte followed by 1568 bytes of key material for a total of 1569 bytes)

         Responses:
            200 - Indicates that client and server have consistent views of repeated-use keys
            401 - Account authentication check failed
            409 -   Indicates that client and server have inconsistent views of repeated-use keys or one or more repeated-use keys could
      not be found

            422 - Invalid request format

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/keys/{identifier}/{device_id}", rtype=RouteType.REQUEST)
def req_v2_keys_identifier_device_id(flow: HTTPFlow, identifier, device_id):
    """
            Fetch public keys for another user
            Retrieves the public identity key and available device prekeys for a specified account or phone-number identity
         Parameters:
            Unidentified-Access-Key
              location: header
              None

            Group-Send-Token
              location: header
              None

            identifier  (required)
              location: path
              the account or phone-number identifier to retrieve keys for

            device_id  (required)
              location: path
              the device id of a single device to retrieve prekeys for, or `*` for all enabled devices

            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/keys/{identifier}/{device_id}", rtype=RouteType.RESPONSE)
def resp_v2_keys_identifier_device_id(flow: HTTPFlow, identifier, device_id):
    """
            Fetch public keys for another user
            Retrieves the public identity key and available device prekeys for a specified account or phone-number identity
         Responses:
            200 - Indicates at least one prekey was available for at least one requested device.
            400 - A group send endorsement and other authorization (account authentication or unidentified-access key) were both provided.
            401 - Account authentication check failed and unidentified-access key or group send endorsement token was not supplied or invalid.
            404 - Requested identity or device does not exist or device has no available prekeys.
            429 - Rate limit exceeded.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/keys", rtype=RouteType.REQUEST)
def req_v2_keys(flow: HTTPFlow):
    """
            Get prekey count
            Gets the number of one-time prekeys uploaded for this device and still available
         Parameters:
            identity
              location: query
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/keys", rtype=RouteType.RESPONSE)
def resp_v2_keys(flow: HTTPFlow):
    """
            Get prekey count
            Gets the number of one-time prekeys uploaded for this device and still available
         Responses:
            200 - Body contains the number of available one-time prekeys for the device.
            401 - Account authentication check failed.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/keys", rtype=RouteType.REQUEST)
def req_v2_keys(flow: HTTPFlow):
    """
            Upload new prekeys
            Upload new pre-keys for this device.
         Parameters:
            identity
              location: query
              None

            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/keys", rtype=RouteType.RESPONSE)
def resp_v2_keys(flow: HTTPFlow):
    """
            Upload new prekeys
            Upload new pre-keys for this device.
         Responses:
            200 - Indicates that new keys were successfully stored.
            401 - Account authentication check failed.
            403 - Attempt to change identity key from a non-primary device.
            422 - Invalid request format.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages", rtype=RouteType.REQUEST)
def req_v1_messages(flow: HTTPFlow):
    """


         Parameters:
            X-Signal-Receive-Stories
              location: header
              None

            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages", rtype=RouteType.RESPONSE)
def resp_v1_messages(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages/uuid/{uuid}", rtype=RouteType.REQUEST)
def req_v1_messages_uuid_uuid(flow: HTTPFlow, uuid):
    """


         Parameters:
            uuid  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages/uuid/{uuid}", rtype=RouteType.RESPONSE)
def resp_v1_messages_uuid_uuid(flow: HTTPFlow, uuid):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages/report/{source}/{messageGuid}", rtype=RouteType.REQUEST)
def req_v1_messages_report_source_messageGuid(flow: HTTPFlow, source, messageGuid):
    """


         Parameters:
            source  (required)
              location: path
              None

            messageGuid  (required)
              location: path
              None

            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages/report/{source}/{messageGuid}", rtype=RouteType.RESPONSE)
def resp_v1_messages_report_source_messageGuid(flow: HTTPFlow, source, messageGuid):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages/{destination}", rtype=RouteType.REQUEST)
def req_v1_messages_destination(flow: HTTPFlow, destination):
    """
            Send a message
            Deliver a message to a single recipient. May be authenticated or unauthenticated; if unauthenticated,
    an unidentifed-access key or group-send endorsement token must be provided, unless the message is a story.

         Parameters:
            Unidentified-Access-Key
              location: header
              The recipient's unidentified access key

            Group-Send-Token
              location: header
              A group send endorsement token covering the recipient. Must not be combined with `Unidentified-Access-Key` or set on a story message.

            User-Agent
              location: header
              None

            destination  (required)
              location: path
              If true, deliver the message only to recipients that are online when it is sent

            story
              location: query
              If true, the message is a story; access tokens are not checked and sending to nonexistent recipients is permitted


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages/{destination}", rtype=RouteType.RESPONSE)
def resp_v1_messages_destination(flow: HTTPFlow, destination):
    """
            Send a message
            Deliver a message to a single recipient. May be authenticated or unauthenticated; if unauthenticated,
    an unidentifed-access key or group-send endorsement token must be provided, unless the message is a story.

         Responses:
            200 - Message was successfully sent
            401 - The message is not a story and the authorization, unauthorized access key, or group send endorsement token is missing or incorrect
            404 - The message is not a story and some the recipient service ID does not correspond to a registered Signal user
            409 - Incorrect set of devices supplied for recipient
            410 - Mismatched registration ids supplied for some recipient devices

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/messages/multi_recipient", rtype=RouteType.REQUEST)
def req_v1_messages_multi_recipient(flow: HTTPFlow):
    """
            Send multi-recipient sealed-sender message
            Deliver a common-payload message to multiple recipients.
    An unidentifed-access key for all recipients must be provided, unless the message is a story.

         Parameters:
            Unidentified-Access-Key
              location: header
              The bitwise xor of the unidentified access keys for every recipient of the message. Will be replaced with group send endorsements

            Group-Send-Token
              location: header
              A group send endorsement token covering recipients of this message. Must not be combined with `Unidentified-Access-Key` or set on a story message.

            User-Agent
              location: header
              None

            online
              location: query
              If true, deliver the message only to recipients that are online when it is sent

            ts
              location: query
              The sender's timestamp for the envelope

            urgent
              location: query
              If true, this message should cause push notifications to be sent to recipients

            story
              location: query
              If true, the message is a story; access tokens are not checked and sending to nonexistent recipients is permitted



    """
    # Implement the function body here
    pass


@api.route("/v1/messages/multi_recipient", rtype=RouteType.RESPONSE)
def resp_v1_messages_multi_recipient(flow: HTTPFlow):
    """
            Send multi-recipient sealed-sender message
            Deliver a common-payload message to multiple recipients.
    An unidentifed-access key for all recipients must be provided, unless the message is a story.

         Responses:
            200 - Message was successfully sent to all recipients
            400 - The envelope specified delivery to the same recipient device multiple times
            401 - The message is not a story and the unauthorized access key or group send endorsement token is missing or incorrect
            404 - The message is not a story and some of the recipient service IDs do not correspond to registered Signal users
            409 - Incorrect set of devices supplied for some recipients
            410 - Mismatched registration ids supplied for some recipient devices


    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/boost/paypal/confirm", rtype=RouteType.REQUEST)
def req_v1_subscription_boost_paypal_confirm(flow: HTTPFlow):
    """


         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/boost/paypal/confirm", rtype=RouteType.RESPONSE)
def resp_v1_subscription_boost_paypal_confirm(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/boost/create", rtype=RouteType.REQUEST)
def req_v1_subscription_boost_create(flow: HTTPFlow):
    """


         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/boost/create", rtype=RouteType.RESPONSE)
def resp_v1_subscription_boost_create(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/boost/receipt_credentials", rtype=RouteType.REQUEST)
def req_v1_subscription_boost_receipt_credentials(flow: HTTPFlow):
    """


         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/boost/receipt_credentials", rtype=RouteType.RESPONSE)
def resp_v1_subscription_boost_receipt_credentials(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/boost/paypal/create", rtype=RouteType.REQUEST)
def req_v1_subscription_boost_paypal_create(flow: HTTPFlow):
    """


         Parameters:
            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/boost/paypal/create", rtype=RouteType.RESPONSE)
def resp_v1_subscription_boost_paypal_create(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/payments/auth", rtype=RouteType.REQUEST)
def req_v1_payments_auth(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/payments/auth", rtype=RouteType.RESPONSE)
def resp_v1_payments_auth(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/payments/conversions", rtype=RouteType.REQUEST)
def req_v1_payments_conversions(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/payments/conversions", rtype=RouteType.RESPONSE)
def resp_v1_payments_conversions(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/profile/{identifier}/{version}", rtype=RouteType.REQUEST)
def req_v1_profile_identifier_version(flow: HTTPFlow, identifier, version):
    """


         Parameters:
            Unidentified-Access-Key
              location: header
              None

            identifier  (required)
              location: path
              None

            version  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/profile/{identifier}/{version}", rtype=RouteType.RESPONSE)
def resp_v1_profile_identifier_version(flow: HTTPFlow, identifier, version):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/profile/{identifier}/{version}/{credentialRequest}", rtype=RouteType.REQUEST
)
def req_v1_profile_identifier_version_credentialRequest(
    flow: HTTPFlow, identifier, version, credentialRequest
):
    """


         Parameters:
            Unidentified-Access-Key
              location: header
              None

            identifier  (required)
              location: path
              None

            version  (required)
              location: path
              None

            credentialRequest  (required)
              location: path
              None

            credentialType
              location: query
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/profile/{identifier}/{version}/{credentialRequest}", rtype=RouteType.RESPONSE
)
def resp_v1_profile_identifier_version_credentialRequest(
    flow: HTTPFlow, identifier, version, credentialRequest
):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/profile/{identifier}", rtype=RouteType.REQUEST)
def req_v1_profile_identifier(flow: HTTPFlow, identifier):
    """


         Parameters:
            Unidentified-Access-Key
              location: header
              None

            Group-Send-Token
              location: header
              None

            User-Agent
              location: header
              None

            identifier  (required)
              location: path
              None

            ca
              location: query
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/profile/{identifier}", rtype=RouteType.RESPONSE)
def resp_v1_profile_identifier(flow: HTTPFlow, identifier):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/profile/identity_check/batch", rtype=RouteType.REQUEST)
def req_v1_profile_identity_check_batch(flow: HTTPFlow):
    """


    Parameters:



    """
    # Implement the function body here
    pass


@api.route("/v1/profile/identity_check/batch", rtype=RouteType.RESPONSE)
def resp_v1_profile_identity_check_batch(flow: HTTPFlow):
    """


    Responses:
       default - default response


    """
    # Implement the function body here
    pass


@api.route("/v1/profile", rtype=RouteType.REQUEST)
def req_v1_profile(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/profile", rtype=RouteType.RESPONSE)
def resp_v1_profile(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/provisioning/{destination}", rtype=RouteType.REQUEST)
def req_v1_provisioning_destination(flow: HTTPFlow, destination):
    """


         Parameters:
            destination  (required)
              location: path
              None

            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/provisioning/{destination}", rtype=RouteType.RESPONSE)
def resp_v1_provisioning_destination(flow: HTTPFlow, destination):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/registration", rtype=RouteType.REQUEST)
def req_v1_registration(flow: HTTPFlow):
    """
            Registers an account
            Registers a new account or attempts to “re-register” an existing account. It is expected that a well-behaved client
    could make up to three consecutive calls to this API:
    1. gets 423 from existing registration lock

    2. gets 409 from device available for transfer

    3. success


         Parameters:
            Authorization  (required)
              location: header
              None

            X-Signal-Agent
              location: header
              None

            User-Agent
              location: header
              None



    """
    # Implement the function body here
    pass


@api.route("/v1/registration", rtype=RouteType.RESPONSE)
def resp_v1_registration(flow: HTTPFlow):
    """
            Registers an account
            Registers a new account or attempts to “re-register” an existing account. It is expected that a well-behaved client
    could make up to three consecutive calls to this API:
    1. gets 423 from existing registration lock

    2. gets 409 from device available for transfer

    3. success


         Responses:
            200 - The phone number associated with the authenticated account was changed successfully
            403 - Verification failed for the provided Registration Recovery Password
            409 - The caller has not explicitly elected to skip transferring data from another device, but a device transfer is technically possible
            422 - The request did not pass validation
            423 -
            429 - Too many attempts


    """
    # Implement the function body here
    pass


@api.route("/v1/config", rtype=RouteType.REQUEST)
def req_v1_config(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/config", rtype=RouteType.RESPONSE)
def resp_v1_config(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/storage/auth", rtype=RouteType.REQUEST)
def req_v1_storage_auth(flow: HTTPFlow):
    """


         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/storage/auth", rtype=RouteType.RESPONSE)
def resp_v1_storage_auth(flow: HTTPFlow):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/backup/auth/check", rtype=RouteType.REQUEST)
def req_v2_backup_auth_check(flow: HTTPFlow):
    """
            Check SVR2 credentials
            Over time, clients may wind up with multiple sets of SVR2 authentication credentials in cloud storage.
    To determine which set is most current and should be used to communicate with SVR2 to retrieve a master key
    (from which a registration recovery password can be derived), clients should call this endpoint
    with a list of stored credentials. The response will identify which (if any) set of credentials are appropriate for communicating with SVR2.

         Parameters:



    """
    # Implement the function body here
    pass


@api.route("/v2/backup/auth/check", rtype=RouteType.RESPONSE)
def resp_v2_backup_auth_check(flow: HTTPFlow):
    """
            Check SVR2 credentials
            Over time, clients may wind up with multiple sets of SVR2 authentication credentials in cloud storage.
    To determine which set is most current and should be used to communicate with SVR2 to retrieve a master key
    (from which a registration recovery password can be derived), clients should call this endpoint
    with a list of stored credentials. The response will identify which (if any) set of credentials are appropriate for communicating with SVR2.

         Responses:
            200 - `JSON` with the check results.
            422 - Provided list of SVR2 credentials could not be parsed
            400 - `POST` request body is not a valid `JSON`


    """
    # Implement the function body here
    pass


@api.route("/v2/backup/auth", rtype=RouteType.REQUEST)
def req_v2_backup_auth(flow: HTTPFlow):
    """
            Generate credentials for SVR2
            Generate SVR2 service credentials. Generated credentials have an expiration time of 30 days
    (however, the TTL is fully controlled by the server side and may change even for already generated credentials).

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v2/backup/auth", rtype=RouteType.RESPONSE)
def resp_v2_backup_auth(flow: HTTPFlow):
    """
            Generate credentials for SVR2
            Generate SVR2 service credentials. Generated credentials have an expiration time of 30 days
    (however, the TTL is fully controlled by the server side and may change even for already generated credentials).

         Responses:
            200 - `JSON` with generated credentials.
            401 - Account authentication check failed.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v3/backup/auth/check", rtype=RouteType.REQUEST)
def req_v3_backup_auth_check(flow: HTTPFlow):
    """
            Check SVR3 credentials
            Over time, clients may wind up with multiple sets of SVR3 authentication credentials in cloud storage.
    To determine which set is most current and should be used to communicate with SVR3 to retrieve a master key
    (from which a registration recovery password can be derived), clients should call this endpoint
    with a list of stored credentials. The response will identify which (if any) set of credentials are
    appropriate for communicating with SVR3.

         Parameters:



    """
    # Implement the function body here
    pass


@api.route("/v3/backup/auth/check", rtype=RouteType.RESPONSE)
def resp_v3_backup_auth_check(flow: HTTPFlow):
    """
            Check SVR3 credentials
            Over time, clients may wind up with multiple sets of SVR3 authentication credentials in cloud storage.
    To determine which set is most current and should be used to communicate with SVR3 to retrieve a master key
    (from which a registration recovery password can be derived), clients should call this endpoint
    with a list of stored credentials. The response will identify which (if any) set of credentials are
    appropriate for communicating with SVR3.

         Responses:
            200 - `JSON` with the check results.
            422 - Provided list of SVR3 credentials could not be parsed
            400 - `POST` request body is not a valid `JSON`


    """
    # Implement the function body here
    pass


@api.route("/v3/backup/auth", rtype=RouteType.REQUEST)
def req_v3_backup_auth(flow: HTTPFlow):
    """
            Generate credentials for SVR3
            Generate SVR3 service credentials. Generated credentials have an expiration time of 30 days
    (however, the TTL is fully controlled by the server side and may change even for already generated credentials).

    If a share-set has been previously set via /v3/backups/share-set, it will be included in the response

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v3/backup/auth", rtype=RouteType.RESPONSE)
def resp_v3_backup_auth(flow: HTTPFlow):
    """
            Generate credentials for SVR3
            Generate SVR3 service credentials. Generated credentials have an expiration time of 30 days
    (however, the TTL is fully controlled by the server side and may change even for already generated credentials).

    If a share-set has been previously set via /v3/backups/share-set, it will be included in the response

         Responses:
            200 - `JSON` with generated credentials and share-set
            401 - Account authentication check failed.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v3/backup/share-set", rtype=RouteType.REQUEST)
def req_v3_backup_share_set(flow: HTTPFlow):
    """
            Set a share-set for the account
            Add a share-set to the account that can later be retrieved at v3/backups/auth or during registration. After
    storing a value with SVR3, clients must store the returned share-set so the value can be restored later.

         Parameters:


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v3/backup/share-set", rtype=RouteType.RESPONSE)
def resp_v3_backup_share_set(flow: HTTPFlow):
    """
            Set a share-set for the account
            Add a share-set to the account that can later be retrieved at v3/backups/auth or during registration. After
    storing a value with SVR3, clients must store the returned share-set so the value can be restored later.

         Responses:
            204 - Successfully set share-set
            401 - Account authentication check failed.

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/sticker/pack/form/{count}", rtype=RouteType.REQUEST)
def req_v1_sticker_pack_form_count(flow: HTTPFlow, count):
    """


         Parameters:
            count  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/sticker/pack/form/{count}", rtype=RouteType.RESPONSE)
def resp_v1_sticker_pack_form_count(flow: HTTPFlow, count):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/create_payment_method/paypal",
    rtype=RouteType.REQUEST,
)
def req_v1_subscription_subscriberId_create_payment_method_paypal(
    flow: HTTPFlow, subscriberId
):
    """


         Parameters:
            subscriberId  (required)
              location: path
              None

            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/create_payment_method/paypal",
    rtype=RouteType.RESPONSE,
)
def resp_v1_subscription_subscriberId_create_payment_method_paypal(
    flow: HTTPFlow, subscriberId
):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/create_payment_method", rtype=RouteType.REQUEST
)
def req_v1_subscription_subscriberId_create_payment_method(
    flow: HTTPFlow, subscriberId
):
    """


         Parameters:
            subscriberId  (required)
              location: path
              None

            type
              location: query
              None

            User-Agent
              location: header
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/create_payment_method", rtype=RouteType.RESPONSE
)
def resp_v1_subscription_subscriberId_create_payment_method(
    flow: HTTPFlow, subscriberId
):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/receipt_credentials", rtype=RouteType.REQUEST
)
def req_v1_subscription_subscriberId_receipt_credentials(flow: HTTPFlow, subscriberId):
    """


         Parameters:
            User-Agent
              location: header
              None

            subscriberId  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/receipt_credentials", rtype=RouteType.RESPONSE
)
def resp_v1_subscription_subscriberId_receipt_credentials(flow: HTTPFlow, subscriberId):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/{subscriberId}", rtype=RouteType.REQUEST)
def req_v1_subscription_subscriberId(flow: HTTPFlow, subscriberId):
    """


         Parameters:
            subscriberId  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/{subscriberId}", rtype=RouteType.RESPONSE)
def resp_v1_subscription_subscriberId(flow: HTTPFlow, subscriberId):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/{subscriberId}", rtype=RouteType.REQUEST)
def req_v1_subscription_subscriberId(flow: HTTPFlow, subscriberId):
    """


         Parameters:
            subscriberId  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/{subscriberId}", rtype=RouteType.RESPONSE)
def resp_v1_subscription_subscriberId(flow: HTTPFlow, subscriberId):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/{subscriberId}", rtype=RouteType.REQUEST)
def req_v1_subscription_subscriberId(flow: HTTPFlow, subscriberId):
    """


         Parameters:
            subscriberId  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/{subscriberId}", rtype=RouteType.RESPONSE)
def resp_v1_subscription_subscriberId(flow: HTTPFlow, subscriberId):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/bank_mandate/{bankTransferType}", rtype=RouteType.REQUEST)
def req_v1_subscription_bank_mandate_bankTransferType(flow: HTTPFlow, bankTransferType):
    """


    Parameters:
       bankTransferType  (required)
         location: path
         None



    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/bank_mandate/{bankTransferType}", rtype=RouteType.RESPONSE)
def resp_v1_subscription_bank_mandate_bankTransferType(
    flow: HTTPFlow, bankTransferType
):
    """


    Responses:
       default - default response


    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/configuration", rtype=RouteType.REQUEST)
def req_v1_subscription_configuration(flow: HTTPFlow):
    """
            Subscription configuration
            Returns all configuration for badges, donation subscriptions, backup subscriptions, and one-time donation (
    "boost" and "gift") minimum and suggested amounts.
         Parameters:



    """
    # Implement the function body here
    pass


@api.route("/v1/subscription/configuration", rtype=RouteType.RESPONSE)
def resp_v1_subscription_configuration(flow: HTTPFlow):
    """
            Subscription configuration
            Returns all configuration for badges, donation subscriptions, backup subscriptions, and one-time donation (
    "boost" and "gift") minimum and suggested amounts.
         Responses:
            200 -


    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/default_payment_method_for_ideal/{setupIntentId}",
    rtype=RouteType.REQUEST,
)
def req_v1_subscription_subscriberId_default_payment_method_for_ideal_setupIntentId(
    flow: HTTPFlow, subscriberId, setupIntentId
):
    """


         Parameters:
            subscriberId  (required)
              location: path
              None

            setupIntentId  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/default_payment_method_for_ideal/{setupIntentId}",
    rtype=RouteType.RESPONSE,
)
def resp_v1_subscription_subscriberId_default_payment_method_for_ideal_setupIntentId(
    flow: HTTPFlow, subscriberId, setupIntentId
):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/default_payment_method/{processor}/{paymentMethodToken}",
    rtype=RouteType.REQUEST,
)
def req_v1_subscription_subscriberId_default_payment_method_processor_paymentMethodToken(
    flow: HTTPFlow, subscriberId, processor, paymentMethodToken
):
    """


         Parameters:
            subscriberId  (required)
              location: path
              None

            processor  (required)
              location: path
              None

            paymentMethodToken  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/default_payment_method/{processor}/{paymentMethodToken}",
    rtype=RouteType.RESPONSE,
)
def resp_v1_subscription_subscriberId_default_payment_method_processor_paymentMethodToken(
    flow: HTTPFlow, subscriberId, processor, paymentMethodToken
):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/level/{level}/{currency}/{idempotencyKey}",
    rtype=RouteType.REQUEST,
)
def req_v1_subscription_subscriberId_level_level_currency_idempotencyKey(
    flow: HTTPFlow, subscriberId, level, currency, idempotencyKey
):
    """


         Parameters:
            subscriberId  (required)
              location: path
              None

            level  (required)
              location: path
              None

            currency  (required)
              location: path
              None

            idempotencyKey  (required)
              location: path
              None


         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route(
    "/v1/subscription/{subscriberId}/level/{level}/{currency}/{idempotencyKey}",
    rtype=RouteType.RESPONSE,
)
def resp_v1_subscription_subscriberId_level_level_currency_idempotencyKey(
    flow: HTTPFlow, subscriberId, level, currency, idempotencyKey
):
    """


         Responses:
            default - default response

         Security:
            authenticatedAccount - basic
            Account authentication is based on Basic authentication schema,
    where `username` has a format of `<user_id>[.<device_id>]`. If `device_id` is not specified,
    user's `main` device is assumed.

    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session", rtype=RouteType.REQUEST)
def req_v1_verification_session(flow: HTTPFlow):
    """


    Parameters:



    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session", rtype=RouteType.RESPONSE)
def resp_v1_verification_session(flow: HTTPFlow):
    """


    Responses:
       default - default response


    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session/{sessionId}", rtype=RouteType.REQUEST)
def req_v1_verification_session_sessionId(flow: HTTPFlow, sessionId):
    """


    Parameters:
       sessionId  (required)
         location: path
         None



    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session/{sessionId}", rtype=RouteType.RESPONSE)
def resp_v1_verification_session_sessionId(flow: HTTPFlow, sessionId):
    """


    Responses:
       default - default response


    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session/{sessionId}", rtype=RouteType.REQUEST)
def req_v1_verification_session_sessionId(flow: HTTPFlow, sessionId):
    """


    Parameters:
       sessionId  (required)
         location: path
         None

       User-Agent
         location: header
         None



    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session/{sessionId}", rtype=RouteType.RESPONSE)
def resp_v1_verification_session_sessionId(flow: HTTPFlow, sessionId):
    """


    Responses:
       default - default response


    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session/{sessionId}/code", rtype=RouteType.REQUEST)
def req_v1_verification_session_sessionId_code(flow: HTTPFlow, sessionId):
    """


    Parameters:
       sessionId  (required)
         location: path
         None

       User-Agent
         location: header
         None



    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session/{sessionId}/code", rtype=RouteType.RESPONSE)
def resp_v1_verification_session_sessionId_code(flow: HTTPFlow, sessionId):
    """


    Responses:
       default - default response


    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session/{sessionId}/code", rtype=RouteType.REQUEST)
def req_v1_verification_session_sessionId_code(flow: HTTPFlow, sessionId):
    """


    Parameters:
       sessionId  (required)
         location: path
         None

       User-Agent
         location: header
         None

       Accept-Language
         location: header
         None



    """
    # Implement the function body here
    pass


@api.route("/v1/verification/session/{sessionId}/code", rtype=RouteType.RESPONSE)
def resp_v1_verification_session_sessionId_code(flow: HTTPFlow, sessionId):
    """


    Responses:
       default - default response


    """
    # Implement the function body here
    pass


addons = [api]
