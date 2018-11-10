import pytest

import pyhibp


@pytest.fixture(autouse=True)
def dev_user_agent(monkeypatch):
    ua_string = pyhibp.pyHIBP_USERAGENT
    monkeypatch.setattr(pyhibp, 'pyHIBP_USERAGENT', ua_string + " (Testing Suite)")
