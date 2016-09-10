.. image:: https://travis-ci.org/vsajip/python-gnupg.svg
   :target: https://travis-ci.org/vsajip/python-gnupg

.. image:: https://coveralls.io/repos/vsajip/python-gnupg/badge.svg
   :target: https://coveralls.io/github/vsajip/python-gnupg


What is it?
===========

The GNU Privacy Guard (gpg, or gpg.exe on Windows) is a command-line program
which provides support for programmatic access via spawning a separate process
to run it and then communicating with that process from your program.

This project, ``python-gnupg``, implements a Python library which takes care
of the internal details and allows its users to generate and manage keys,
encrypt and decrypt data, and sign and verify messages.

Installation
============

Installing from PyPI
--------------------

You can install this package from the Python Package Index (pyPI) by running::

    pip install python-gnupg


Installing from a source distribution archive
---------------------------------------------
To install this package from a source distribution archive, do the following:

1. Extract all the files in the distribution archive to some directory on your
   system.
2. In that directory, run ``python setup.py install``.
3. Optionally, run ``python test_gnupg.py`` to ensure that the package is
   working as expected.

Credits
=======

* The developers of the GNU Privacy Guard.
* The original version of this module was developed by Andrew Kuchling.
* It was improved by Richard Jones.
* It was further improved by Steve Traugott.

The present incarnation, based on the earlier versions, uses the ``subprocess``
module and so works on Windows as well as Unix/Linux platforms. It's not,
however, 100% backwards-compatible with earlier incarnations.

Change log
==========

N.B: GCnn refers to an issue nn on Google Code.

0.4.0 (future)
--------------

Released: Not yet

0.3.9
-----

Released: 2016-09-10

* Fixed #38: You can now request information about signatures against
  keys. Thanks to SunDwarf for the suggestion and patch, which was used
  as a basis for this change.

* Fixed #49: When exporting keys, no attempt is made to decode the output when
  armor=False is specified.

* Fixed #53: A ``FAILURE`` message caused by passing an incorrect passphrase
  is handled.

* Handled ``EXPORTED`` and ``EXPORT_RES`` messages while exporting keys. Thanks
  to Marcel Pörner for the patch.

* Fixed #54: Improved error message shown when gpg is not available.

* Fixed #55: Added support for ``KEY_CONSIDERED`` while verifying.

* Avoided encoding problems with filenames under Windows. Thanks to Kévin
  Bernard-Allies for the patch.

* Fixed #57: Used a better mechanism for comparing keys.


0.3.8
-----

Released: 2015-09-24

* Fixed #22: handled ``PROGRESS`` messages during verification and signing.

* Fixed #26: handled ``PINENTRY_LAUNCHED`` messages during verification,
  decryption and key generation.

* Fixed #28: Allowed a default Name-Email to be computed even when neither of
  ``LOGNAME`` and ``USERNAME`` are in the environment.

* Fixed #29: Included test files missing from the tarball in previous versions.

* Fixed #39: On Python 3.x, passing a text instead of a binary stream caused
  file decryption to hang due to a ``UnicodeDecodeError``. This has now been
  correctly handled: The decryption fails with a "no data" status.

* Fixed #41: Handled Unicode filenames correctly by encoding them on 2.x using
  the file system encoding.

* Fixed #43: handled ``PINENTRY_LAUNCHED`` messages during key export. Thanks
  to Ian Denhardt for looking into this.

* Hide the console window which appears on Windows when gpg is spawned.
  Thanks to Kévin Bernard-Allies for the patch.

* Subkey fingerprints are now captured.

* The returned value from the ``list_keys`` method now has a new attribute,
  ``key_map``, which is a dictionary mapping key and subkey fingerprints to
  the corresponding key's dictionary. With this change, you don't need to
  iterate over the (potentially large) returned list to search for a key with
  a given fingerprint - the ``key_map`` dict will take you straight to the key
  info, whether the fingerprint you have is for a key or a subkey. Thanks to
  Nick Daly for the initial suggestion.

0.3.7
-----

Released: 2014-12-07

Signed with PGP key: Vinay Sajip (CODE SIGNING KEY) <vinay_sajip@yahoo.co.uk>

Key Fingerprint    : CA74 9061 914E AC13 8E66 EADB 9147 B477 339A 9B86

* Added an ``output`` keyword parameter to the ``sign`` and
  ``sign_file`` methods, to allow writing the signature to a file.
  Thanks to Jannis Leidel for the patch.

* Allowed specifying ``True`` for the ``sign`` keyword parameter,
  which allows use of the default key for signing and avoids having to
  specify a key id when it's desired to use the default. Thanks to
  Fabian Beutel for the patch.

* Used a uniform approach with subprocess on Windows and POSIX: shell=True
  is not used on either.

* When signing/verifying, the status is updated to reflect any expired or
  revoked keys or signatures.

* Handled 'NOTATION_NAME' and 'NOTATION_DATA' during verification.

* Fixed #1, #16, #18, #20: Quoting approach changed, since now shell=False.

* Fixed #14: Handled 'NEED_PASSPHRASE_PIN' message.

* Fixed #8: Added a scan_keys method to allow scanning of keys without the
  need to import into a keyring. Thanks to Venzen Khaosan for the suggestion.

* Fixed #5: Added '0x' prefix when searching for keys. Thanks to Aaron Toponce
  for the report.

* Fixed #4: Handled 'PROGRESS' message during encryption. Thanks to Daniel
  Mills for the report.

* Fixed #3: Changed default encoding to Latin-1.

* Fixed #2: Raised ValueError if no recipients were specified
  for an asymmetric encryption request.

* Handled 'UNEXPECTED' message during verification. Thanks to
  David Andersen for the patch.

* Replaced old range(len(X)) idiom with enumerate().

* Refactored ``ListKeys`` / ``SearchKeys`` classes to maximise use of common
  functions.

* Fixed GC94: Added ``export-minimal`` and ``armor`` options when exporting
  keys. This addition was inadvertently left out of 0.3.6.

0.3.6
-----

Released: 2014-02-05

* Fixed GC82: Enabled fast random tests on gpg as well as gpg2.
* Fixed GC85: Avoided deleting temporary file to preserve its permissions.
* Fixed GC87: Avoided writing passphrase to log.
* Fixed GC95: Added ``verify_data()`` method to allow verification of
  signatures in memory.
* Fixed GC96: Regularised end-of-line characters.
* Fixed GC98: Rectified problems with earlier fix for shell injection.

0.3.5
-----

Released: 2013-08-30

* Added improved shell quoting to guard against shell injection.
* Fixed GC76: Added ``search_keys()`` and ``send_keys()`` methods.
* Fixed GC77: Allowed specifying a symmetric cipher algorithm.
* Fixed GC78: Fell back to utf-8 encoding when no other could be determined.
* Fixed GC79: Default key length is now 2048 bits.
* Fixed GC80: Removed the Name-Comment default in key generation.

0.3.4
-----

Released: 2013-06-05

* Fixed GC65: Fixed encoding exception when getting version.
* Fixed GC66: Now accepts sets and frozensets where appropriate.
* Fixed GC67: Hash algorithm now captured in sign result.
* Fixed GC68: Added support for ``--secret-keyring``.
* Fixed GC70: Added support for multiple keyrings.

0.3.3
-----

Released: 2013-03-11

* Fixed GC57: Handled control characters in ``list_keys()``.
* Fixed GC61: Enabled fast random for testing.
* Fixed GC62: Handled ``KEYEXPIRED`` status.
* Fixed GC63: Handled ``NO_SGNR`` status.

0.3.2
-----

Released: 2013-01-17

* Fixed GC56: Disallowed blank values in key generation.
* Fixed GC57: Handled colons and other characters in ``list_keys()``.
* Fixed GC59/GC60: Handled ``INV_SGNR`` status during verification and removed
  calls requiring interactive password input from doctests.

0.3.1
-----

Released: 2012-09-01

* Fixed GC45: Allowed additional arguments to gpg executable.
* Fixed GC50: Used latin-1 encoding in tests when it's known to be required.
* Fixed GC51: Test now returns non-zero exit status on test failure.
* Fixed GC53: Now handles ``INV_SGNR`` and ``KEY_NOT_CREATED`` statuses.
* Fixed GC55: Verification and decryption now return trust level of signer in
  integer and text form.

0.3.0
-----

Released: 2012-05-12

* Fixed GC49: Reinstated Yann Leboulanger's change to support subkeys
  (accidentally left out in 0.2.7).

0.2.9
-----

Released: 2012-03-29

* Fixed GC36: Now handles ``CARDCTRL`` and ``POLICY_URL`` messages.
* Fixed GC40: Now handles ``DECRYPTION_INFO``, ``DECRYPTION_FAILED`` and
  ``DECRYPTION_OKAY`` messages.
* The ``random_binary_data file`` is no longer shipped, but constructed by the
  test suite if needed.

0.2.8
-----

Released: 2011-09-02

* Fixed GC29: Now handles ``IMPORT_RES`` while verifying.
* Fixed GC30: Fixed an encoding problem.
* Fixed GC33: Quoted arguments for added safety.

0.2.7
-----

Released: 2011-04-10

* Fixed GC24: License is clarified as BSD.
* Fixed GC25: Incorporated Daniel Folkinshteyn's changes.
* Fixed GC26: Incorporated Yann Leboulanger's subkey change.
* Fixed GC27: Incorporated hysterix's support for symmetric encryption.
* Did some internal cleanups of Unicode handling.

0.2.6
-----

Released: 2011-01-25

* Fixed GC14: Should be able to accept passphrases from GPG-Agent.
* Fixed GC19: Should be able to create a detached signature.
* Fixed GC21/GC23: Better handling of less common responses from GPG.

0.2.5
-----

Released: 2010-10-13

* Fixed GC11/GC16: Detached signatures can now be created.
* Fixed GC3: Detached signatures can be verified.
* Fixed GC12: Better support for RSA and IDEA.
* Fixed GC15/GC17: Better support for non-ASCII input.

0.2.4
-----

Released: 2010-03-01

* Fixed GC9: Now allows encryption without armor and the ability to encrypt
  and decrypt directly to/from files.

0.2.3
-----

Released: 2010-01-07

* Fixed GC7: Made sending data to process threaded and added a test case.
  With a test data file used by the test case, the archive size has gone up
  to 5MB (the size of the test file).

0.2.2
-----

Released: 2009-10-06

* Fixed GC5/GC6: Added ``--batch`` when specifying ``--passphrase-fd`` and
  changed the name of the distribution file to add the ``python-`` prefix.

0.2.1
-----

Released: 2009-08-07

* Fixed GC2: Added ``handle_status()`` method to the ``ListKeys`` class.

0.2.0
-----

Released: 2009-07-16

* Various changes made to support Python 3.0.

0.1.0
-----

Released: 2009-07-04

* Initial release.
