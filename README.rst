pyHIBP (pyHave I Been Pwned)
============================

An interface to Troy Hunt's 'Have I Been Pwned?' (herein referred to as HIBP) public API.

Goals
=====
* Synchronize to the latest HIBP API.
* For breaches and pastes, act as an intermediary; return the JSON as received from the service.
* For passwords, return True or False based on the result of the query.
* Raise appropriate exceptions for other errors.

Security
========
* For passwords, the option to supply a plaintext password to check is provided as an implementation convenience.
    * However, passwords will always be SHA1 hashed prior to submission for checking.
    * Similarly, checking passwords will be performed via POST-submission of the SHA1 hash.
