import hashlib

import requests
import six

import pyHIBP

PWNED_PASSWORDS_API_BASE_URI = "https://api.pwnedpasswords.com/"
PWNED_PASSWORDS_API_ENDPOINT_PASSWORD_SEARCH = "pwnedpassword/"
PWNED_PASSWORDS_API_ENDPOINT_RANGE_SEARCH = "range/"


def _process_response(response):
    """
    Process the `requests` response from the call to the Pwned Passwords API endpoints.

    :param response: The response object from a call to `requests`
    :return: True if HTTP Status 200, False if 404. NotImplementedError if the API returns an unexpected HTTP status code.
    """
    if response.status_code == 200:
        # The request was successful (the supplied password was breached)
        return True
    elif response.status_code == 404:
        # The request was successful, (the supplied password was not breached)
        return False
    else:
        # We /should/ get one of the above error codes. If not, raise an error.
        raise NotImplementedError("Returned HTTP status code of " + str(response.status_code) + " was not expected.")


def is_password_breached(password=None, sha1_hash=None):
    """
    Checks the HIBP breached password corpus for a breached password. Only the password or sha1_hash
    parameter is required to be set.

    Note that while the HIBP endpoint does have a originalPasswordIsAHash parameter, passwords submitted
    to this function will successfully process a supplied SHA1 hash password, since we pre-hash on our end.

    :param password: The raw password to check. Will be converted to a SHA1 hash prior to submission.
    :param sha1_hash: The SHA1 hash of the password to check.
    :return: The number of times the given password was found within the Pwned Passwords corpus, if the password was found.
    If the password was not found, returns numerical zero (0).
    """
    if password is None and sha1_hash is None:
        raise AttributeError("You must provide either a password or sha1_hash")
    elif password is not None and not isinstance(password, six.string_types):
        raise AttributeError("The provided password is not a string")
    elif sha1_hash is not None and not isinstance(sha1_hash, six.string_types):
        raise AttributeError("The provided sha1_hash is not a string")

    if password and sha1_hash and hashlib.sha1(password.encode('utf-8')).hexdigest() != sha1_hash.lower():
        # We want to make sure we accurately tell the user if the password was breached,
        # and providing 'True' when the password and SHA are different is extremely ambiguous.
        raise AttributeError("A password and SHA1 hash were supplied (only one is needed), but they did not match")
    elif password and not sha1_hash:
        # Only submit the SHA1 hash to the backend
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()

    uri = PWNED_PASSWORDS_API_BASE_URI + PWNED_PASSWORDS_API_ENDPOINT_PASSWORD_SEARCH + sha1_hash
    headers = {'user-agent': pyHIBP.pyHIBP_USERAGENT}

    resp = requests.get(url=uri, headers=headers)
    
    if _process_response(response=resp):
        return resp.text
    else:
        return 0


def range_search(first_5_hash_chars=None, sha1_hash=None):
    """
    Execute a search for a password via the k-anonymity model, checking for hashes which match a specified
    prefix instead of supplying the full hash.
    
    Uses the first five characters of a SHA-1 hash to provide a list of hash suffixes along with the
    number of times that hash appears in the data set. In doing so, the API is not provided the information
    required to reconstruct the password (e.g., by brute-forcing the hash).
    
    Either ``first_5_hash_chars`` or ``sha1_hash`` must be specified. If both are specified, raises
    AttributeError if first_5_hash_chars does not match sha1_hash[0:4]. In this instance, only the
    first five hash characters of sha1_hash will be provided to the API.
    
    Suffix example: 0018A45C4D1DEF81644B54AB7F969B88D65:1
    
    :param first_5_hash_chars: The first five characters of a SHA-1 hash string.
    :param sha1_hash: A full SHA-1 hash.
    :return: If ``first_5_hash_chars`` is supplied, a [list] of hash suffixes. If ``sha1_hash`` is supplied,
    and the password was found in the corpus, an Integer representing the number of times the password is in
    the data set; if not found, Integer zero (0) is returned.
    """
    if not first_5_hash_chars and not sha1_hash:
        raise AttributeError("Either first_5_hash_chars or sha1_hash must be provided.")
    elif first_5_hash_chars is not None and not isinstance(first_5_hash_chars, six.string_types):
        raise AttributeError("first_5_hash_chars must be a string type.")
    elif sha1_hash is not None and not isinstance(sha1_hash, six.string_types):
        raise AttributeError("sha1_hash must be a string type.")
    elif sha1_hash and first_5_hash_chars and not sha1_hash[0:4] == first_5_hash_chars:
        raise AttributeError("first_5_hash_chars does not match sha1_hash[0:4]")
    elif sha1_hash:
        first_5_hash_chars = sha1_hash[0:4]
    
    uri = PWNED_PASSWORDS_API_BASE_URI + PWNED_PASSWORDS_API_ENDPOINT_RANGE_SEARCH + first_5_hash_chars
    resp = requests.get(uri=uri, headers=pyHIBP.pyHIBP_USERAGENT)
    
    if resp.status_code != 200:
        # The HTTP Status should always be 200 for this request
        raise RuntimeError("Response from the endpoint was not HTTP200; this should not happen. Code was: " + resp.status_code)
    elif not sha1_hash:
        # Return the list of hash suffixes.
        return resp.text.split()
    else:
        # Since the full SHA-1 hash was provided, check to see if it was in the resultant hash suffixes returned.
        response_lines = resp.text.split()
        
        for hash_suffix in response_lines:
            if sha1_hash[4:] in hash_suffix:
                # We found the full hash, so return
                return hash_suffix.split(':')[1]
        
        # If we get here, there was no match to the supplied SHA-1 hash; return zero.
        return 0
