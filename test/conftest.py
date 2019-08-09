import time

import pytest

import pyhibp
from pyhibp import __version__


@pytest.fixture(autouse=True)
def dev_user_agent(monkeypatch):
    """
    All calls to the HIBP/PwnedPasswords endpoints require a user agent to be set. So set one on all tests.
    """
    ua_string = "pyHIBP/{version} (A Python interface to the public HIBP API; Testing suite)".format(
        version=__version__.__version__,
    )
    pyhibp.set_user_agent(ua=ua_string)


@pytest.fixture(name="sleep")
def sleep_test(request):
    """
    For the endpoints where a rate limit is specified, or we want to be kind to the endpoint and not
    needlessly execute requests too quickly, this specifies a test module-configurable sleep duration.

    Usage: Specify a module-level variable named `_PYTEST_SLEEP_DURATION`, and the value is an int,
    specifying the number of seconds to sleep between test invocations.
    """
    sleep_duration = getattr(request.module, "_PYTEST_SLEEP_DURATION", 0)
    time.sleep(sleep_duration)
