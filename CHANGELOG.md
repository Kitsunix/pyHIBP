pyHIBP Changelog
================
v4.1.0 (2020-04-06)
------------------------
- Adds the capability to request that the Pwned Passwords API return padding to the responses to calls made via
  ``pwnedpasswords``. Set the parameter ``add_padding`` to ``True`` on ``suffix_search`` or ``is_password_breached``.
  See [the HIBP API](https://haveibeenpwned.com/API/v3#PwnedPasswordsPadding) for additional information.

v4.0.0 (2019-08-11)
------------------------
- **Breaking API change**: The HIBP API now requires an API key for calls which search by account. This means calls to
  ``pyhibp.get_account_breaches()`` and ``pyhibp.get_pastes()``. API keys can be obtained [the HIBP website](https://haveibeenpwned.com/API/Key),
  and must be loaded into the module by calling ``pyhibp.set_api_key(key="your_key")`` prior to calling the affected
  functions.
- The other functions inside ``pyhibp``, as well as ``pwnedpasswords``, do not require an API key to use.
- As a note, our testing harness has not been tested against valid API keys, however we anticipate no issues. If issues
  are discovered, please raise an issue with details, ideally with a merge request to fix the issue.
- **A User Agent must now be manually set**: As per the HIBP API, the User-Agent header set in calls to the API must
  reflect the name of the calling application. Directly from the API documentation, "the user agent should accurately
  describe the nature of the API consumer such that it can be clearly identified in the request. Not doing so may result
  in the request being blocked." As such, users of this module must now set the User-Agent by calling
  ``pyhibp.set_user_agent(ua=ua_string)``, where ``ua_string`` is a string which identifies the application implementing
  the ``pyhibp`` module.
- **Python 2.7 Support Dropped**: With Python 2.7 support being dropped in January 2020, as stated in the notes for v3.0.0
  and v3.1.0, ``pyhibp`` is dropping support for Python 2.7.
- **Function modified**: ``suffix_search(hash_prefix=prefix)`` is now the method to search for hash suffixes. The compatability
  shim left when introducing the function in v3.1.0 has been removed (and thus ``first_5_hash_chars`` is no longer a valid
  parameter to the function ``is_password_breached()``).
- **Return type changes**: As per the changelog from v3.1.0, the return type for empty sets has changed as follows for the
  following functions in the ``pyhibp`` module:
    - ``get_account_breaches`` -> ``[] / list``
    - ``get_all_breaches`` -> ``[] / list``
    - ``get_single_breach`` -> ``{} / dict``
    - ``get_pastes`` -> ``[] / list``

v3.2.0 (2020-03-28)
-----------------------
- **FINAL SUPPORTED PYTHON 2.7 RELEASE**: All following releases will require Python 3. CPython discontinued support as of
  January 1, 2020, and we dropped support in v4.0.0. (Yes, we dropped support and are releasing a backport; ironic.)
- **Backported functions (from v4.0.0)**: The following functions are required to consume the API, either in general (user agent), or for querying for specific account information (API key).
    - `pyhibp.set_user_agent(ua=agent)`: The HIBP API requires the calling application to set a descriptive UA string to
      describe the application consuming the API. This must be called prior to invoking any functions in
      `pyhibp` or `pwnedpasswords` which actually make requests to the HIBP API.
    - `pyhibp.set_api_key(key=your_key)`: For `pyhibp` functions which retrieve information about specific accounts, an
      API key must be purchased from the HIBP website. This must be set prior to calling the relevant functions.
- Note: As this is was a backport, this change is not in the main master branch of source control, however the tagged release may [be found here](https://gitlab.com/kitsunix/pyHIBP/pyHIBP/-/tags/v3.2.0).

v3.1.0 (2019-06-30)
-----------------------
- **New function**: ``pwnedpasswords.suffix_search(hash_prefix=prefix)`` was created in order to have a dedicated function
  return the suffix list.
- **Function modification notice**: ``pwnedpasswords.is_password_breached`` will be modified in an upcoming release to
  remove the ability to search for suffixes; use ``suffix_search(hash_prefix=prefix)`` instead. The parameter
  ``first_5_hash_chars`` will be removed as a consequence.
- **Upcoming return type change for empty sets**: For the functions ``get_account_breaches``, ``get_all_breaches``,
  ``get_single_breach``, and ``get_pastes``--all contained in the ``pyhibp`` module--when no items would be returned
  from the HIBP backend, the returned item will be an empty object matching the standard return type for the function,
  and not a Boolean ``False``. This will occur when ``v4.0.0`` is released. Return types will be:
    - ``get_account_breaches`` -> ``[] / list``
    - ``get_all_breaches`` -> ``[] / list``
    - ``get_single_breach`` -> ``{} / dict``
    - ``get_pastes`` -> ``[] / list``
- As a reminder, Python 2.7 support will be dropped from support in the near future. This will occur at the same time
  as the removal of the range search functionality available via ``pwnedpasswords.is_password_breached(first_5_hash_chars=prefix)``
  so as to minimize disruption.

v3.0.0 (2018-11-10)
-------------------
- **Backwards Incompatible Change**: The package name has been changed to fall in-line with the PEP 8 guideline calling
  for [all lowercase characters in package/module names](https://www.python.org/dev/peps/pep-0008/#package-and-module-names).
  Existing code will need to change invocations of ``pyHIBP`` to ``pyhibp``.
    - We will, however, still refer to the package/module as _pyHIBP_ when it is used outside of the context of Python code.
- **Future Python 2 Deprecation**: As per PEP 373, [Python 2.7.x support ends on 2020-01-01](https://www.python.org/dev/peps/pep-0373/#maintenance-releases).
  That being said, we will be dropping Python 2 as a supported version _prior_ to this date.
- The `requests` dependency has been bumped to require versions at or above `2.20.0` (due to CVE-2018-18074 affecting
  the `requests` package for older versions).

v2.1.1 (2018-09-18)
-------------------
- Bug fix: Corrected the capitalization of UA header, which was causing the majority of calls to ``get_account_breaches()`` to fail.

v2.1.0 (2018-07-21)
------------------
- **FUNCTION MOVED**: ``is_password_breached()`` has been fully removed from the core ``pyhibp`` module. It may be accessed
  from the ``pwnedpasswords`` module.
- Quasi-internal change: Relocated the GitLab repository to be in a group with the Jupyter Notebooks examples
  providing an interactive usage example.

v2.0.2 (2018-04-14)
-------------------
- **Final deprecation warning**: The ``pyhibp.is_password_breached`` shim will be removed in a future release. This
  function has been moved to the ``pwnedpasswords`` module, via ``from pyhibp import pwnedpasswords``.
- Internal: Shifts requirements/requirements.txt into setup.py, as as pip>=10 explicitly internalizes the method previously used
  to fill the install_requires variable.
- Internal: Removes vcversioner as a build requirement, opting to define the version in __version__.py.

v2.0.1 (2018-03-09)
-------------------
- **Deprecation warning**: The function ``is_password_breached`` has moved from ``pyhibp`` to the module named ``pwnedpasswords``. A wrapper has
  been left to ease transition to the new function; access via ``from pyhibp import pwnedpasswords``.
- The Pwned Passwords API version 2 has been released, and as such the following changes were made:
- ``is_password_breached`` no longer transmits the full SHA-1 hash to the Pwned Passwords API endpoint. This means any
  password that we want to check--such as a user's signup password--is secure. This is accomplished by transmitting
  the first 5 characters of the SHA-1 hash, and parsing the resultant list of partial SHA hashes for a match to the
  supplied password, or SHA-1 hash.
- The behavior of the prior ``is_password_breached()`` as implemented in v2.0.0 which submitted the full SHA-1 hash
  was dropped for added security.
- In addition to ``password`` and ``sha1_hash``, ``pwnedpasswords.is_password_breached()`` now accepts ``first_5_hash_chars``.
  This is to be set to the first five characters of a SHA-1 hash, and will return a list of partial hashes, along with
  the number of times the hash value in question was found in the Pwned Passwords corpus. This could be useful if you
  wish to perform verification of the hashes in the application importing this module.
- If ``password`` or ``sha1_hash`` is provided, the return value will now be an integer, corresponding to the number
  of times that password was located in the Pwned Passwords corpus, as per above. Integer zero (0) is returned if there
  was no match located, so one can still execute a call in the manner of ``if pw.is_password_breached():``.
- Unrelated to the code changes, the Pwned Passwords API (i.e, ``is_password_breached``) is no longer rate-limited.
  For more information, please see Troy Hunt's [post announcing Pwned Passwords v2](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/).


v2.0.0 (2018-02-01)
-------------------
- Initial release.
