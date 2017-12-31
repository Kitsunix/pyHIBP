import time

import pytest


@pytest.fixture(autouse=True)
def rate_limit():
    # The HIBP API has a ratelimit of 1500ms. Sleep for 2 seconds.
    time.sleep(2)
