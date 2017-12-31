import hashlib

import pytest

import pyHIBP


TEST_ACCOUNT = "test@example.com"
TEST_DOMAIN = "adobe.com"
TEST_PASSWORD = "password"
TEST_PASSWORD_SHA1_HASH = hashlib.sha1(TEST_PASSWORD.encode('utf-8')).hexdigest()
# At least, I doubt someone would have used this (only directly specifying here for deterministic tests...)
TEST_PASSWORD_LIKELY_NOT_COMPROMISED = "&Q?t{%i|n+&qpyP/`/Lyr3<rK|N/M//;u^!fnR+j'lM)A+IGcgRGs[6mLY7yV-|x0bYB&L.JyaJ"
TEST_PASSWORD_LIKELY_NOT_COMPROMISED_HASH = hashlib.sha1(TEST_PASSWORD_LIKELY_NOT_COMPROMISED.encode('utf-8')).hexdigest()


def test_get_breaches_account():
    # get_breaches(account=TEST_ACCOUNT, domain=None, truncate_response=False, include_unverified=False):
    resp = pyHIBP.get_breaches(account=TEST_ACCOUNT)
    assert isinstance(resp, list)
    # As of a manual test, there were 46 accounts for the test@example.com; so >=20 is safe.
    assert len(resp) >= 20
    assert isinstance(resp[0], dict)


def test_get_breaches_account_with_truncation():
    # get_breaches(account=TEST_ACCOUNT, domain=None, truncate_response=True, include_unverified=False):
    resp = pyHIBP.get_breaches(account=TEST_ACCOUNT, truncate_response=True)
    assert isinstance(resp, list)
    assert len(resp) >= 20
    assert isinstance(resp[0], dict)
    # The individual dicts are only the name of the breached website (since we're truncating)
    item = resp[0]
    assert len(item) == 1
    assert 'Name' in item
    assert 'DataClasses' not in item


def test_get_breaches_domain():
    # get_breaches(account=None, domain="adobe.com", truncate_response=True, include_unverified=False):
    resp = pyHIBP.get_breaches(domain="adobe.com")
    # The API returns the information as a list (specifically, request's .json() does)
    assert isinstance(resp, list)
    # We're only expecting one item
    assert len(resp) == 1
    assert isinstance(resp[0], dict)
    assert resp[0]['Name'] == "Adobe"


def test_get_breaches_retrieve_all_breaches():
    # get_breaches(account=None, domain=None, truncate_response=True, include_unverified=False):
    resp = pyHIBP.get_breaches()
    assert isinstance(resp, list)
    assert len(resp) > 50


def test_get_breaches_retrieve_all_breaches_with_unverified():
    # get_breaches(account=None, domain=None, truncate_response=False, include_unverified=True):
    resp = pyHIBP.get_breaches(include_unverified=True)
    assert isinstance(resp, list)
    assert len(resp) > 50
    has_unverified = False
    for item in resp:
        if not item['IsVerified']:
            has_unverified = True
            # If we see any unverified items, that's enough.
            break
    assert has_unverified


def test_is_password_breached_password_only_breached():
    # is_password_breached(password=TEST_PASSWORD, sha1_hash=None):
    assert pyHIBP.is_password_breached(password=TEST_PASSWORD)


def test_is_password_breached_sha1hash_only_breached():
    # is_password_breached(password=None, sha1_hash=TEST_PASSWORD_SHA1_HASH):
    assert pyHIBP.is_password_breached(sha1_hash=TEST_PASSWORD_SHA1_HASH)


def test_is_password_breached_password_only_not_breached():
    # is_password_breached(password=TEST_PASSWORD_LIKELY_NOT_COMPROMISED, sha1_hash=None):
    assert not pyHIBP.is_password_breached(password=TEST_PASSWORD_LIKELY_NOT_COMPROMISED)


def test_is_password_breached_sha1hash_only_not_breached():
    # is_password_breached(password=None, sha1_hash=TEST_PASSWORD_LIKELY_NOT_COMPROMISED_HASH):
    assert not pyHIBP.is_password_breached(sha1_hash=TEST_PASSWORD_LIKELY_NOT_COMPROMISED_HASH)


def test_is_password_breached_password_and_sha1hash_matches():
    # is_password_breached(password=TEST_PASSWORD, sha1_hash=TEST_PASSWORD_SHA1_HASH):
    assert pyHIBP.is_password_breached(password=TEST_PASSWORD, sha1_hash=TEST_PASSWORD_SHA1_HASH)


def test_is_password_breached_password_and_sha1hash_mismatch():
    # is_password_breached(password="NotThePassword", sha1_hash=TEST_PASSWORD_SHA1_HASH):
    with pytest.raises(AttributeError):
        pyHIBP.is_password_breached(password="NotThePassword", sha1_hash=TEST_PASSWORD_SHA1_HASH)
