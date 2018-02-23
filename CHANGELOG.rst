v2.0.1 (2018-MM-DD)
-------------------
- **Deprecation warning**: The function ``is_password_breached`` has moved from ``pyHIBP`` to the module named ``pwnedpasswords``. A wrapper has
  been left to ease transition to the new function; access via ``from pyHIBP import pwnedpasswords``.
- The Pwned Passwords API version 2 has been released, and as such the following new functions have been added...
- ``is_password_breached`` in `pwnedpasswords` now returns Integer zero (0) if a password was not breached, and an Integer
  count of the number of times the password was found in the Pwned Password corpus if the password's hash was found.
- ``range_search`` supplies only five characters of the SHA-1 hash of a password to the Pwned Passwords server, permitting
  a potentially secure password to remain just that, secure. after all, if you don't need to provide the full hash, why do so?
- While the Pwned Passwords service can be trusted, one may desire to use the function to securely check passwords provided
  during registration to a live webservice. As such, protecting the confidentiality of the password is a paramount concern.
  As such, by providing five hash characters, the breached password corpus can only provide what it knows about. Determining
  if the password was indeed breached is up to this module's code.
- With that said, it is **strongly** suggested that implementers of this package SHOULD use the `range_search` function over
  the ``is_password_breached`` function. Implementers MAY use the ``is_password_breached`` function, but MUST be aware that doing
  so publicizes the full SHA-1 hash for a given password to the Pwned Passwords API. The current function of the
  ``is_password_breached`` function MAY be supplanted via calls to ``range_search``, and ultimately replaced, however given that
  the Pwned Passwords API has an endpoint for it, the function may be maintained for parity with the API's endpoints, but the
  function might be renamed to directly show that the function is--technically--not as secure. This portion is still under consideration.

v2.0.0 (2018-02-01)
-------------------
- Initial release.
