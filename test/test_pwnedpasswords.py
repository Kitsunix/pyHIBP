import hashlib

import pytest

import pyhibp
from pyhibp import pwnedpasswords as pw

# While the pwnedpasswords endpoint does not have a limit, be kind anyway. 1 second sleep.
_PYTEST_SLEEP_DURATION = 1

TEST_PASSWORD = "password"
TEST_PASSWORD_SHA1_HASH = hashlib.sha1(TEST_PASSWORD.encode('utf-8')).hexdigest()
# At least, I doubt someone would have used this (only directly specifying here for deterministic tests)
TEST_PASSWORD_LIKELY_NOT_COMPROMISED = "&Q?t{%i|n+&qpyP/`/Lyr3<rK|N/M//;u^!fnR+j'lM)A+IGcgRGs[6mLY7yV-|x0bYB&L.JyaJ"
TEST_PASSWORD_LIKELY_NOT_COMPROMISED_HASH = hashlib.sha1(TEST_PASSWORD_LIKELY_NOT_COMPROMISED.encode('utf-8')).hexdigest()


class TestIsPasswordBreached(object):
    def test_no_params_provided_raises(self):
        # is_password_breached(password=None, first_5_hash_chars=None, sha1_hash=None):
        with pytest.raises(AttributeError) as execinfo:
            pw.is_password_breached()
        assert "Either password or sha1_hash must be provided." in str(execinfo.value)

    def test_password_not_string_raises(self):
        # is_password_breached(password=123, first_5_hash_chars=None, sha1_hash=None):
        with pytest.raises(AttributeError) as execinfo:
            pw.is_password_breached(password=123)
        assert "password must be a string." in str(execinfo.value)

    def test_sha1_hash_not_string_raises(self):
        # is_password_breached(password=None, first_5_hash_chars=None, sha1_hash=123):
        with pytest.raises(AttributeError) as execinfo:
            pw.is_password_breached(sha1_hash=123)
        assert "sha1_hash must be a string." in str(execinfo.value)

    @pytest.mark.usefixtures('sleep')
    def test_provide_password_to_function(self):
        resp = pw.is_password_breached(password="password")
        assert isinstance(resp, int)
        assert resp > 100

    @pytest.mark.usefixtures('sleep')
    def test_ensure_case_sensitivity_of_hash_does_not_matter(self):
        resp_one = pw.is_password_breached(sha1_hash=TEST_PASSWORD_SHA1_HASH.lower())
        assert isinstance(resp_one, int)
        assert resp_one > 100

        resp_two = pw.is_password_breached(sha1_hash=TEST_PASSWORD_SHA1_HASH.upper())
        assert isinstance(resp_two, int)
        assert resp_two > 100

        assert resp_one == resp_two

    @pytest.mark.usefixtures('sleep')
    def test_zero_count_result_for_non_breached_password(self):
        resp = pw.is_password_breached(password=TEST_PASSWORD_LIKELY_NOT_COMPROMISED)
        assert isinstance(resp, int)
        assert resp == 0


class TestSuffixSearch(object):
    def test_no_param_provided_raises(self):
        # def suffix_search(hash_prefix=None):
        with pytest.raises(AttributeError) as execinfo:
            pw.suffix_search()
        assert "hash_prefix must be a supplied, and be a string." in str(execinfo.value)

    def test_hash_prefix_not_string_raises(self):
        # def suffix_search(hash_prefix=123):
        with pytest.raises(AttributeError) as execinfo:
            pw.suffix_search(hash_prefix=123)
        assert "hash_prefix must be a supplied, and be a string." in str(execinfo.value)

    def test_first_5_hash_chars_not_length_five_raises(self):
        # suffix_search(hash_prefix="123456"):
        with pytest.raises(AttributeError) as execinfo:
            pw.suffix_search(hash_prefix="123456")
        assert "hash_prefix must be of length 5." in str(execinfo.value)

    @pytest.mark.usefixtures('sleep')
    @pytest.mark.parametrize("add_padding", [True, False])
    def test_list_of_hashes_returned(self, add_padding):
        """
        Test all parameters: The response format for all parameters is the same.
        """
        resp = pw.suffix_search(hash_prefix=TEST_PASSWORD_SHA1_HASH[0:5], add_padding=add_padding)

        assert isinstance(resp, list)
        assert len(resp) > 100
        match_found = False
        for entry in resp:
            partial_hash, count = entry.split(":")
            if not add_padding:
                if TEST_PASSWORD_SHA1_HASH[5:] == partial_hash.lower():
                    match_found = True
                    break
            elif add_padding:
                if count == "0":
                    match_found = True
                    break
        assert match_found

    def test_user_agent_must_be_set_or_raise(self, monkeypatch):
        """
        The HIBP backend requires a User-Agent; ensure we're forcing one to be set.

        Additionally, `is_password_breached` calls `suffix_search`, so we only need to check this function.
        """
        monkeypatch.setitem(pyhibp.pyHIBP_HEADERS, 'User-Agent', None)
        with pytest.raises(RuntimeError) as execinfo:
            pw.suffix_search(hash_prefix=TEST_PASSWORD_SHA1_HASH[0:5])
        assert "The User-Agent must be set. Call pyhibp.set_user_agent(ua=your_agent_string) first." in str(execinfo.value)
