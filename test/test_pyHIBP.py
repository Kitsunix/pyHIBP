import pytest

import pyhibp


# The breach/paste endpoints enforce a 1500 ms rate limit; so sleep 2 seconds.
_PYTEST_SLEEP_DURATION = 2

TEST_ACCOUNT = "test@example.com"
TEST_DOMAIN = "adobe.com"
TEST_DOMAIN_NAME = "Adobe"
# Very likely to not exist; SHA-1 hash of the SHA-1 hash of the string "password"
TEST_NONEXISTENT_ACCOUNT_NAME = "353e8061f2befecb6818ba0c034c632fb0bcae1b"


class TestGetAccountBreaches(object):
    @pytest.mark.usefixtures('sleep')
    def test_get_breaches_api_key_must_be_specified_or_raise(self):
        with pytest.raises(RuntimeError) as excinfo:
            # Will raise because an API key has not been set on this request.
            pyhibp.get_account_breaches(account=TEST_ACCOUNT)
        assert "A HIBP API key is required for this call. Call pyhibp.set_api_key(key=your_key) first." in str(excinfo.value)

    @pytest.mark.skip("Unable to test due to lack of purchased API key")
    @pytest.mark.usefixtures('sleep')
    def test_get_breaches_account(self):
        # get_account_breaches(account=TEST_ACCOUNT, domain=None, truncate_response=False, include_unverified=False):
        resp = pyhibp.get_account_breaches(account=TEST_ACCOUNT)
        assert isinstance(resp, list)
        # As of a manual test, there were 46 accounts for the test@example.com; so >=20 is safe.
        assert len(resp) >= 20
        assert isinstance(resp[0], dict)

    @pytest.mark.skip("Unable to test due to lack of purchased API key")
    @pytest.mark.usefixtures('sleep')
    def test_get_breaches_account_with_domain(self):
        # get_account_breaches(account=TEST_ACCOUNT, domain=TEST_DOMAIN, truncate_response=False, include_unverified=False):
        resp = pyhibp.get_account_breaches(account=TEST_ACCOUNT, domain=TEST_DOMAIN)
        assert isinstance(resp, list)
        # We're limiting the domain; so we only expect one breach to be returned
        assert len(resp) == 1
        assert isinstance(resp[0], dict)
        assert resp[0]['Name'] == TEST_DOMAIN_NAME

    @pytest.mark.skip("Unable to test due to lack of purchased API key")
    @pytest.mark.usefixtures('sleep')
    def test_get_breaches_account_with_truncation(self):
        # get_account_breaches(account=TEST_ACCOUNT, domain=None, truncate_response=True, include_unverified=False):
        resp = pyhibp.get_account_breaches(account=TEST_ACCOUNT, truncate_response=True)
        assert isinstance(resp, list)
        assert len(resp) >= 20
        assert isinstance(resp[0], dict)
        # The individual dicts are only the name of the breached website (since we're truncating)
        item = resp[0]
        assert len(item) == 1
        assert 'Name' in item
        assert 'DataClasses' not in item

    @pytest.mark.skip("Unable to test due to lack of purchased API key")
    @pytest.mark.usefixtures('sleep')
    def test_get_breaches_retrieve_all_breaches_with_unverified(self):
        # get_account_breaches(account=TEST_ACCOUNT, domain=None, truncate_response=False, include_unverified=True):
        resp = pyhibp.get_account_breaches(account=TEST_ACCOUNT, include_unverified=True)
        assert isinstance(resp, list)
        assert len(resp) > 50
        has_unverified = False
        for item in resp:
            if not item['IsVerified']:
                has_unverified = True
                # If we see any unverified items, that's enough.
                break
        assert has_unverified

    @pytest.mark.skip("Unable to test due to lack of purchased API key")
    @pytest.mark.usefixtures('sleep')
    def test_get_breaches_return_false_if_no_accounts(self):
        # get_account_breaches(account=TEST_PASSWORD_SHA1_HASH, domain=None, truncate_response=False, include_unverified=False):
        resp = pyhibp.get_account_breaches(account=TEST_NONEXISTENT_ACCOUNT_NAME)
        assert not resp
        assert isinstance(resp, list)

    @pytest.mark.usefixtures('use_fake_api_key')
    def test_get_breaches_raise_if_account_is_not_specified(self):
        # get_account_breaches(account=1, domain=None, truncate_response=False, include_unverified=False):
        with pytest.raises(AttributeError) as excinfo:
            # Will raise because the account must be a string
            pyhibp.get_account_breaches(account=None)
        assert "The account parameter must be specified, and must be a string" in str(excinfo.value)

    @pytest.mark.usefixtures('use_fake_api_key')
    def test_get_breaches_raise_if_account_is_not_string(self):
        # get_account_breaches(account=1, domain=None, truncate_response=False, include_unverified=False):
        with pytest.raises(AttributeError) as excinfo:
            # Will raise because the account must be a string
            pyhibp.get_account_breaches(account=1)
        assert "The account parameter must be specified, and must be a string" in str(excinfo.value)

    @pytest.mark.usefixtures('use_fake_api_key')
    def test_get_breaches_raise_if_domain_is_not_string(self):
        # get_account_breaches(account=TEST_ACCOUNT, domain=1, truncate_response=False, include_unverified=False):
        with pytest.raises(AttributeError) as excinfo:
            # Will raise because the domain must be a string
            pyhibp.get_account_breaches(account=TEST_ACCOUNT, domain=1)
        assert "The domain parameter, if specified, must be a string" in str(excinfo.value)

    @pytest.mark.usefixtures('use_fake_api_key')
    def test_user_agent_must_be_set_or_raise(self, monkeypatch):
        """
        The HIBP backend requires a User-Agent; ensure we're forcing one to be set on all functions
        """
        monkeypatch.setitem(pyhibp.pyHIBP_HEADERS, 'User-Agent', None)
        with pytest.raises(RuntimeError) as execinfo:
            pyhibp.get_account_breaches(account=TEST_ACCOUNT)
        assert "The User-Agent must be set. Call pyhibp.set_user_agent(ua=your_agent_string) first." in str(execinfo.value)


class TestGetAllBreaches(object):
    @pytest.mark.usefixtures('sleep')
    def test_get_all_breaches(self):
        # def get_all_breaches(domain=None):
        resp = pyhibp.get_all_breaches()
        assert isinstance(resp, list)
        assert len(resp) > 50
        assert isinstance(resp[0], dict)

    @pytest.mark.usefixtures('sleep')
    def test_get_all_breaches_filter_to_domain(self):
        # def get_all_breaches(domain=TEST_DOMAIN):
        resp = pyhibp.get_all_breaches(domain=TEST_DOMAIN)
        assert isinstance(resp, list)
        # There can be multiple breaches in the system for a given domain
        assert len(resp) >= 1
        assert isinstance(resp[0], dict)
        assert resp[0]['Name'] == TEST_DOMAIN_NAME

    @pytest.mark.usefixtures('sleep')
    def test_get_all_breaches_false_if_domain_does_not_exist(self):
        resp = pyhibp.get_all_breaches(domain=TEST_NONEXISTENT_ACCOUNT_NAME)
        assert not resp
        assert isinstance(resp, list)

    def test_get_all_breaches_raise_if_not_string(self):
        # def get_all_breaches(domain=1):
        with pytest.raises(AttributeError) as excinfo:
            # Will raise because the domain must be a string
            pyhibp.get_all_breaches(domain=1)
        assert "The domain parameter, if specified, must be a string" in str(excinfo.value)

    def test_user_agent_must_be_set_or_raise(self, monkeypatch):
        """
        The HIBP backend requires a User-Agent; ensure we're forcing one to be set on all functions
        """
        monkeypatch.setitem(pyhibp.pyHIBP_HEADERS, 'User-Agent', None)
        with pytest.raises(RuntimeError) as execinfo:
            pyhibp.get_all_breaches()
        assert "The User-Agent must be set. Call pyhibp.set_user_agent(ua=your_agent_string) first." in str(execinfo.value)


class TestGetSingleBreach(object):
    @pytest.mark.usefixtures('sleep')
    def test_get_single_breach(self):
        # get_single_breach(breach_name=TEST_DOMAIN_NAME)
        resp = pyhibp.get_single_breach(breach_name=TEST_DOMAIN_NAME)
        assert isinstance(resp, dict)
        assert resp['Name'] == TEST_DOMAIN_NAME

    @pytest.mark.usefixtures('sleep')
    def test_get_single_breach_when_breach_does_not_exist(self):
        # get_single_breach(breach_name="ThisShouldNotExist")
        resp = pyhibp.get_single_breach(breach_name="ThisShouldNotExist")
        assert not resp
        assert isinstance(resp, dict)

    def test_get_single_breach_raise_when_breach_name_not_specified(self):
        # get_single_breach()
        with pytest.raises(AttributeError) as excinfo:
            # Will error because the breach_name must be specified
            pyhibp.get_single_breach()
        assert "The breach_name must be specified, and be a string" in str(excinfo.value)

    def test_get_single_breach_raise_when_breach_name_is_not_a_string(self):
        # get_single_breach(breach_name=1)
        with pytest.raises(AttributeError) as excinfo:
            # Will raise because the breach_name must be a string
            pyhibp.get_single_breach(breach_name=1)
        assert "The breach_name must be specified, and be a string" in str(excinfo.value)

    def test_user_agent_must_be_set_or_raise(self, monkeypatch):
        """
        The HIBP backend requires a User-Agent; ensure we're forcing one to be set on all functions
        """
        monkeypatch.setitem(pyhibp.pyHIBP_HEADERS, 'User-Agent', None)
        with pytest.raises(RuntimeError) as execinfo:
            pyhibp.get_single_breach(breach_name=TEST_DOMAIN_NAME)
        assert "The User-Agent must be set. Call pyhibp.set_user_agent(ua=your_agent_string) first." in str(execinfo.value)


class TestGetPastes(object):
    @pytest.mark.usefixtures('sleep')
    def test_get_pastes_api_key_must_be_specified_or_raise(self):
        with pytest.raises(RuntimeError) as excinfo:
            # Will raise because an API key has not been set on this request.
            pyhibp.get_pastes(email_address=TEST_ACCOUNT)
        assert "A HIBP API key is required for this call. Call pyhibp.set_api_key(key=your_key) first." in str(excinfo.value)

    @pytest.mark.skip("Unable to test due to lack of purchased API key")
    @pytest.mark.usefixtures('sleep')
    def test_get_pastes(self):
        print(pyhibp.pyHIBP_HEADERS)
        # get_pastes(email_address=TEST_ACCOUNT):
        resp = pyhibp.get_pastes(email_address=TEST_ACCOUNT)
        # The return value is a list, containing multiple dicts (1 or more)
        assert isinstance(resp, list)
        for item in resp:
            assert isinstance(item, dict)

    @pytest.mark.skip("Unable to test due to lack of purchased API key")
    @pytest.mark.usefixtures('sleep')
    def test_get_pastes_return_false_if_no_account(self):
        print(pyhibp.pyHIBP_HEADERS)
        # get_pastes(email_address=TEST_ACCOUNT):
        resp = pyhibp.get_pastes(email_address=TEST_NONEXISTENT_ACCOUNT_NAME + "@example.invalid")
        assert not resp
        assert isinstance(resp, list)

    @pytest.mark.usefixtures('use_fake_api_key')
    def test_get_pastes_raise_if_email_not_specified(self):
        # get_pastes():
        with pytest.raises(AttributeError) as excinfo:
            pyhibp.get_pastes()
        assert "The email address supplied must be provided, and be a string" in str(excinfo.value)

    @pytest.mark.usefixtures('use_fake_api_key')
    def test_get_pastes_raise_if_email_not_string(self):
        # get_pastes(email_address=1):
        with pytest.raises(AttributeError) as excinfo:
            pyhibp.get_pastes(email_address=1)
        assert "The email address supplied must be provided, and be a string" in str(excinfo.value)

    @pytest.mark.usefixtures('use_fake_api_key')
    def test_user_agent_must_be_set_or_raise(self, monkeypatch):
        """
        The HIBP backend requires a User-Agent; ensure we're forcing one to be set on all functions
        """
        monkeypatch.setitem(pyhibp.pyHIBP_HEADERS, 'User-Agent', None)
        with pytest.raises(RuntimeError) as execinfo:
            pyhibp.get_pastes(email_address=TEST_ACCOUNT)
        assert "The User-Agent must be set. Call pyhibp.set_user_agent(ua=your_agent_string) first." in str(execinfo.value)


class TestGetDataClasses(object):
    def test_user_agent_must_be_set_or_raise(self, monkeypatch):
        """
        The HIBP backend requires a User-Agent; ensure we're forcing one to be set on all functions
        """
        monkeypatch.setitem(pyhibp.pyHIBP_HEADERS, 'User-Agent', None)
        with pytest.raises(RuntimeError) as execinfo:
            pyhibp.get_data_classes()
        assert "The User-Agent must be set. Call pyhibp.set_user_agent(ua=your_agent_string) first." in str(execinfo.value)

    @pytest.mark.usefixtures('sleep')
    def test_get_data_classes(self):
        # get_data_classes():
        resp = pyhibp.get_data_classes()
        assert isinstance(resp, list)
        assert len(resp) > 10
        assert "Passwords" in resp


class TestMiscellaneous(object):
    @pytest.mark.skip("Unable to test due to lack of purchased API key")
    @pytest.mark.usefixtures('sleep')
    def test_raise_if_invalid_format_submitted(self):
        # For example, if a null (0x00) character is submitted to an endpoint.
        with pytest.raises(RuntimeError) as execinfo:
            pyhibp.get_account_breaches(account="\0")
        assert "HTTP 400" in str(execinfo.value)
