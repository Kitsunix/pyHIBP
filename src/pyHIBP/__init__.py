import hashlib

import requests
import six

HIBP_API_BASE_URI = "https://haveibeenpwned.com/api/v2/"
HIBP_API_ENDPOINT_BREACH_SINGLE = "breach/"
HIBP_API_ENDPOINT_BREACHES = "breaches"
HIBP_API_ENDPOINT_BREACHED_ACCT = "breachedaccount/"
HIBP_API_ENDPOINT_DATA_CLASSES = "dataclasses"
HIBP_API_ENDPOINT_PASTES = "pasteaccount/"
HIBP_API_ENDPOINT_PWNED_PASSWORDS = "pwnedpassword"

# The HIBP API requires that a useragent be set.
pyHIBP_USERAGENT = "pyHIBP: A Python Interface to the Public HIBP API"


def __process_response(response):
    """
    Process the `requests` response from the call to the HIBP API endpoints.
    :param response: The response object from a call to `requests`
    :return: True if HTTP Status 200, False if 404. Raises RuntimeError on API-defined status codes of
    400, 403, 429; NotImplementedError if the API returns an unexpected HTTP status code.
    """
    if response.status_code == 200:
        # The request was successful (a password/breach/paste was found)
        return True
    elif response.status_code == 404:
        # The request was successful, though the item wasn't found
        return False
    elif response.status_code == 400:
        # Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)
        raise RuntimeError(
            "HTTP 400 - Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)")
    elif response.status_code == 403:
        # Forbidden — no user agent has been specified in the request
        raise RuntimeError("HTTP 403 - User agent required for HIBP API requests, but no user agent was sent to the API endpoint")
    elif response.status_code == 429:
        # Too many requests — the rate limit has been exceeded
        raise RuntimeError(
            "HTTP 429 - Rate limit exceeded: API rate limit is 1500ms. Retry-After header was: " + response.headers['Retry-After']
        )
    else:
        # We /should/ get one of the above error codes. If not, raise an error.
        raise NotImplementedError("Returned HTTP status code of " + str(response.status_code) + " was not expected.")


def get_breaches(account=None, domain=None, truncate_response=False, include_unverified=False):
    """
    Gets breaches for a specified account, a specified domain, both, or neither.

    If account and domain are not specified, all breaches in the HIBP database are returned. If
    either (or both) are specified, then the returned results are restricted to the specified information.

    :param account: The user's account name (such as an email address or a user-name). Default None.
    :param domain: The domain to check for breaches. Default None.
    :param truncate_response: If ``account`` is specified, truncates the response down to the breach names.
    Does not truncate response if ``account`` is left as None. Default False.
    :param include_unverified: If set to True, unverified breaches are included in the result. Default False.
    :return: The decoded JSON information about the breach if the breach was found, otherwise False.
    """
    # Account/Domain don't need to be specified, but they must be text if so.
    if account is not None and not isinstance(account, six.text_type):
        raise AttributeError("<account> must be a string")
    if domain is not None and not isinstance(domain, six.text_type):
        raise AttributeError("<domain> must be a string")

    # Build the URI
    uri = HIBP_API_BASE_URI
    headers = {'user-agent': pyHIBP_USERAGENT}
    if account:
        # Get a single account's breaches
        uri += HIBP_API_ENDPOINT_BREACHED_ACCT + account
    else:
        # Get all breaches in the HIBP system
        uri += HIBP_API_ENDPOINT_BREACHES

    # Build the query string payload (requests drops params when None)
    # (and the HIBP backend ignores those that don't apply)
    query_string_payload = {
        "domain": domain,
        "truncateResponse": truncate_response,
        "includeUnverified": include_unverified,
    }
    resp = requests.get(uri, params=query_string_payload, headers=headers)
    print(resp.status_code)
    if __process_response(response=resp):
        return resp.json()
    else:
        return False


def get_single_breach(breach_name=None):
    """
    Returns a single breach's information from the HIBP's database.

    :param breach_name: The breach to retrieve. Required.
    :return: The decoded JSON information about the breach if the breach was found, otherwise False.
    """
    if not isinstance(breach_name, six.text_type):
        raise AttributeError("breach_name must be specified")
    uri = HIBP_API_BASE_URI + HIBP_API_ENDPOINT_BREACH_SINGLE + breach_name
    headers = {'user-agent': pyHIBP_USERAGENT}
    resp = requests.get(uri, headers=headers)
    if __process_response(resp):
        return resp.json()
    else:
        return False


def get_pastes(email_address=None):
    """
    Retrieve all pastes for a specified email address.
    :param email_address: The email address to search. Required.
    :return: The decoded JSON information about any pastes if found, otherwise False.
    """
    if not isinstance(email_address, six.text_type):
        raise AttributeError("The email address supplied must be provided, and be a text string.")
    uri = HIBP_API_BASE_URI + HIBP_API_ENDPOINT_PASTES + email_address
    headers = {'user-agent': pyHIBP_USERAGENT}
    resp = requests.get(uri, headers=headers)
    if __process_response(response=resp):
        return resp.json()
    else:
        return False


def get_data_classes():
    """
    Retrieves all available data classes from the HIBP API.

    :return: Data classes decoded from JSON
    """
    uri = HIBP_API_BASE_URI + HIBP_API_ENDPOINT_DATA_CLASSES
    headers = {'user-agent': pyHIBP_USERAGENT}
    resp = requests.get(uri, headers=headers)
    if __process_response(response=resp):
        return resp.json()
    else:
        # This path really shouldn't return false
        raise RuntimeError("HIBP API returned HTTP404 on a request for data classes.")


def is_password_breached(password=None, sha1_hash=None):
    """
    Checks the HIBP breached password corpus for a breached password. Only the password or sha1_hash
    parameter is required to be set.

    Note that while the HIBP endpoint does have a originalPasswordIsAHash parameter, passwords submitted
    to this function will successfully process a supplied SHA1 hash password, since we pre-hash on our end.

    :param password: The raw password to check. Will be converted to a SHA1 hash prior to submission.
    :param sha1_hash: The SHA1 hash of the password to check.
    :return: True if the password was in the HIBP password corpus, otherwise False.
    """
    if password is None and sha1_hash is None:
        raise AttributeError("You must provide either a password or sha1_hash")
    elif password is not None and not isinstance(password, six.text_type):
        raise AttributeError("The provided password is not a string")
    elif sha1_hash is not None and not isinstance(sha1_hash, six.text_type):
        raise AttributeError("The provided sha1_hash is not a string")

    if password and sha1_hash:
        if hashlib.sha1(password.encode('utf-8')).hexdigest() != sha1_hash.lower():
            raise AttributeError("A password and SHA1 hash were supplied (only one is needed), but they did not match")
    elif password and not sha1_hash:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()

    uri = HIBP_API_BASE_URI + HIBP_API_ENDPOINT_PWNED_PASSWORDS
    headers = {'user-agent': pyHIBP_USERAGENT}
    payload = {'Password': sha1_hash}

    resp = requests.post(uri, data=payload, headers=headers)
    return __process_response(response=resp)
