import hashlib

import pytest

import pyHIBP


TEST_ACCOUNT = "test@example.com"
TEST_DOMAIN = "adobe.com"
TEST_PASSWORD = "password"
TEST_PASSWORD_SHA1_HASH = hashlib.sha1(TEST_PASSWORD.encode('utf-8')).hexdigest()
# At least, I doubt someone would have used this...
TEST_PASSWORD_LIKELY_NOT_COMPROMISED = "&Q?t{%i|n+&qpyP/`/Lyr3<rK|N/M//;u^!fnR+j'lM)A+IGcgRGs[6mLY7yV-|x0bYB&L.JyaJ"
TEST_PASSWORD_LIKELY_NOT_COMPROMISED_HASH = hashlib.sha1(TEST_PASSWORD_LIKELY_NOT_COMPROMISED.encode('utf-8')).hexdigest()


def test_get_breaches_account():
    # get_breaches(account=TEST_ACCOUNT, domain=None, truncate_response=False, include_unverified=False):
    pass


def test_get_breaches_account_with_truncation():
    # get_breaches(account=TEST_ACCOUNT, domain=None, truncate_response=True, include_unverified=False):
    pass


def test_get_breaches_domain():
    pass


def test_get_breaches_retrieve_all_breaches():
    pass


def test_get_breaches_retrieve_all_breaches_with_unverified():
    pass


def test_is_password_breached_password_only_breached():
    # is_password_breached(password=TEST_PASSWORD, sha1_hash=None):
    pass


def test_is_password_breached_sha1hash_only_breached():
    # is_password_breached(password=None, sha1_hash=TEST_PASSWORD_SHA1_HASH):
    pass


def test_is_password_breached_password_only_not_breached():
    # is_password_breached(password=TEST_PASSWORD_LIKELY_NOT_COMPROMISED, sha1_hash=None):
    pass


def test_is_password_breached_sha1hash_only_not_breached():
    # is_password_breached(password=None, sha1_hash=TEST_PASSWORD_LIKELY_NOT_COMPROMISED_HASH):
    pass


def test_is_password_breached_password_and_sha1hash_matches():
    # is_password_breached(password=TEST_PASSWORD, sha1_hash=TEST_PASSWORD_SHA1_HASH):
    pass


def test_is_password_breached_password_and_sha1hash_mismatch():
    # is_password_breached(password="NotThePassword", sha1_hash=TEST_PASSWORD_SHA1_HASH):
    pass