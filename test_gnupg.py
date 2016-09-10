# -*- coding: utf-8 -*-
"""
A test harness for gnupg.py.

Copyright (C) 2008-2016 Vinay Sajip. All rights reserved.
"""
import doctest
import logging
import os.path
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest

import gnupg

__author__ = "Vinay Sajip"
__date__  = "$10-Sep-2016 08:38:57$"

ALL_TESTS = True

logger = logging.getLogger(__name__)

GPGBINARY = os.environ.get('GPGBINARY', 'gpg')

KEYS_TO_IMPORT = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (MingW32)

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
=sqld
-----END PGP PUBLIC KEY BLOCK-----"""

SIGNED_KEYS="""-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mI0EVcnKUQEEAKWazmfM0kbvDdw7Kos2NARaX67c8iJ3GOBimUvYLj4VR3Mqrm34
ZdLlS8jCmid+qoisefvGW5uw5Q3gIs0mdEdUpFKlXNiIja/Dg/FHjjJPPCjfzDTh
Q03EYA7QvOnXZXhYPBqK7NitsNXW4lPnIJdanLx7yMuL+2Xb+tF39mwnABEBAAG0
LUpvc2h1YSBDYWx2ZXJ0IChBIHRlc3QgdXNlcikgPGpjQGV4YW1wbGUuY29tPoi3
BBMBCAAhBQJVycpRAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJELxvNQ+z
0EB2jcED/0lHKaEkyd6cj0Zckf9luIkZ4Hno/vRCquTI7c3aPjS3qmE8mOvKSBCV
+SamPdRM7DdjkdBrrKy2HtiDqbM+1/CdXuQka2SlJWyLCJe48+KWfBpqlY3N4t53
JjHRitDB+hC8njWTV5prli6EgsBPAF+ZkO0iZhlsMmWdDWgqDpGRiJwEEAEIAAYF
AlXJym8ACgkQBXzPZYwHT9oiiQQAvPF8ubwRopnXIMDQgSxKyFDM1MI1w/wb4Okd
/MkMeZSmdcHJ6pEymp5bYciCBuLW+jw0vZWza3YloO/HtuppnF6A9a1UvYcp/diI
O5qkQqYPlui1PJl7hQ014ioniMfOcC4X/r6PDbC78Pczje0Yh9AOqNGeCyNyNdlc
pjaHb0m4jQRVycpRAQQAo9JjW75F5wTVVO552cGCZWqZvDyBt9+IkoK9Bc+ggdn5
6R8QVCihYuaSzcSEN84zHaR3MmGKHraCmCSlfe7w0d41Dlns0P03KMdIZOGrm045
F8TXdSSPQOv5tA4bz3k2lGD0zB8l4NUWFaZ5fzw2i73FF4O/FwCU8xd/JCKVPkkA
EQEAAYifBBgBCAAJBQJVycpRAhsMAAoJELxvNQ+z0EB2xLYD/i3tKirQlVB+32WP
wggstqDp1BlUBmDb+4Gndpg4l7omJTTyOsF26SbYgXZqAdEd5T/UfpEla0DKiBYh
2/CFYXadkgX/ME+GTetTmD4hHoBNmdXau92buXsIXkwh+JR+RC3cl2U6tWb/MIRd
zvJiok8W8/FT/QrEjIa2etN2d+KR
=nNBX
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mI0EVcnKNgEEANIVlIUyRXWHP/ljdMEA8B5NxecRCKusUIPxeapk2do5UCZgR1q8
5wOP4K/+W3Uj85ylOOCNTFYKRozAHsPMAmQ38W93DZYqFbG6d7rwMvz4pVe0wUtj
SBINoKnoEDZwx3erxFKOkp/5fF3NoYSIx9a0Ds21ESk0TAuH5Tg934YhABEBAAG0
MVdpbnN0b24gU21pdGggKEEgdGVzdCB1c2VyKSA8d2luc3RvbkBleGFtcGxlLmNv
bT6ItwQTAQgAIQUCVcnKNgIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRAF
fM9ljAdP2h05A/4vmnxV1MwcOhJTHZys5g2/j5UoZG7V7lPGpJaojSAIVzYXZtwT
5A7OY8Nl21kIY6gnZlgbTRpHN8Qq2wRKAyW5o6wQvuN16CW4bmGjoHYRGPqkeM0w
G40W/v88JXrYDNNe/68g4pnPsZ3J0oMLbRvCaDQQHXBuZNJrT1sOxl9Of7iNBFXJ
yjYBBACmHbs0PdOF8NEGc+fEtmdKOSKOkrcvg1wTu1KFFTBFEbseHOCNpx+R6lfO
ZiZmHGdKeJhTherfjHaY5jmvyDWq5TLZXK61quNsWxmY2zJ0SRwrIG/CWi4bMi5t
JNc23vMumkz4X5g7x0Ea7xEWkcYBn0H6sZDAtb8d8mrlWkMekQARAQABiJ8EGAEI
AAkFAlXJyjYCGwwACgkQBXzPZYwHT9pQIwP8D9/VroykSE2J3gy0S6HC287jXqXF
0zWejUAQtWUSSRx4esqfLE8lfae6+LDHO8D0Bf6YUJmu7ATOZP2/TIas7JrNvXWc
NKWl2MHEAGUYq8utCjZ3dKKhaV7UvcY4PyLIpFteNkOz4wFe6C0Mm+1NYwokIFyh
zPBq9eFk7Xx9Wrc=
=HT6N
-----END PGP PUBLIC KEY BLOCK-----
"""


def is_list_with_len(o, n):
    return isinstance(o, list) and len(o) == n

BASE64_PATTERN = re.compile(r'^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$', re.I)

def get_key_data(s):
    lines = s.split('\n')
    result = ''
    for line in lines:
        m = BASE64_PATTERN.match(line)
        if m:
            result += line
    return result

def compare_keys(k1, k2):
    "Compare ASCII keys"
    # See issue #57: we need to compare only the actual key data,
    # ignoring things like spurious blank lines
    return get_key_data(k1) != get_key_data(k2)

class GPGTestCase(unittest.TestCase):
    def setUp(self):
        hd = os.path.join(os.getcwd(), 'keys')
        if os.path.exists(hd):
            self.assertTrue(os.path.isdir(hd),
                            "Not a directory: %s" % hd)
            shutil.rmtree(hd)
        self.homedir = hd
        self.gpg = gpg = gnupg.GPG(gnupghome=hd, gpgbinary=GPGBINARY)
        v = gpg.version
        if v:
            if v >= (2,):  # pragma: no cover
                gpg.options = ['--debug-quick-random']
            else:
                gpg.options = ['--quick-random']
        self.test_fn = test_fn = 'random_binary_data'
        if not os.path.exists(test_fn):  # pragma: no cover
            data_file = open(test_fn, 'wb')
            data_file.write(os.urandom(5120 * 1024))
            data_file.close()

    def test_environment(self):
        "Test the environment by ensuring that setup worked"
        hd = self.homedir
        self.assertTrue(os.path.exists(hd) and os.path.isdir(hd),
                        "Not an existing directory: %s" % hd)

    def test_list_keys_initial(self):
        "Test that initially there are no keys"
        logger.debug("test_list_keys_initial begins")
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 0),
                        "Empty list expected")
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 0),
                        "Empty list expected")
        logger.debug("test_list_keys_initial ends")

    def generate_key(self, first_name, last_name, domain, passphrase=None):
        "Generate a key"
        params = {
            'Key-Type': 'DSA',
            'Key-Length': 1024,
            'Subkey-Type': 'ELG-E',
            'Subkey-Length': 2048,
            'Name-Comment': 'A test user',
            'Expire-Date': 0,
        }
        options = self.gpg.options or []
        if '--debug-quick-random' in options or '--quick-random' in options:
            # If using the fake RNG, a key isn't regarded as valid
            # unless its comment has the text (insecure!) in it.
            params['Name-Comment'] = 'A test user (insecure!)'
        params['Name-Real'] = '%s %s' % (first_name, last_name)
        params['Name-Email'] = ("%s.%s@%s" % (first_name, last_name,
                                              domain)).lower()
        if passphrase is None:
            passphrase = ("%s%s" % (first_name[0], last_name)).lower()
        params['Passphrase'] = passphrase
        cmd = self.gpg.gen_key_input(**params)
        return self.gpg.gen_key(cmd)

    def do_key_generation(self):
        "Test that key generation succeeds"
        result = self.generate_key("Barbara", "Brown", "beta.com")
        self.assertNotEqual(None, result, "Non-null result")
        return result

    def test_key_generation_with_invalid_key_type(self):
        "Test that key generation handles invalid key type"
        params = {
            'Key-Type': 'INVALID',
            'Key-Length': 1024,
            'Subkey-Type': 'ELG-E',
            'Subkey-Length': 2048,
            'Name-Comment': 'A test user',
            'Expire-Date': 0,
            'Name-Real': 'Test Name',
            'Name-Email': 'test.name@example.com',
        }
        cmd = self.gpg.gen_key_input(**params)
        result = self.gpg.gen_key(cmd)
        self.assertFalse(result.data, 'Null data result')
        self.assertEqual(None, result.fingerprint, 'Null fingerprint result')

    def test_key_generation_with_colons(self):
        "Test that key generation handles colons in key fields"
        params = {
            'key_type': 'RSA',
            'name_real': 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19',
            'name_comment': 'dummy comment',
            'name_email': 'test.name@example.com',
        }
        cmd = self.gpg.gen_key_input(**params)
        result = self.gpg.gen_key(cmd)
        keys = self.gpg.list_keys()
        self.assertEqual(len(keys), 1)
        key = keys[0]
        uids = key['uids']
        self.assertEqual(len(uids), 1)
        uid = uids[0]
        self.assertEqual(uid, 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19 '
                              '(dummy comment) <test.name@example.com>')

    def test_key_generation_with_escapes(self):
        "Test that key generation handles escape characters"
        cmd = self.gpg.gen_key_input(name_comment='Funny chars: '
                                                  '\\r\\n\\f\\v\\0\\b',
                                     name_real='Test Name',
                                     name_email='test.name@example.com')
        result = self.gpg.gen_key(cmd)
        keys = self.gpg.list_keys()
        self.assertEqual(len(keys), 1)
        key = keys[0]
        uids = key['uids']
        self.assertEqual(len(uids), 1)
        uid = uids[0]
        self.assertEqual(uid, 'Test Name (Funny chars: '
                              '\r\n\x0c\x0b\x00\x08) <test.name@example.com>')

    def test_key_generation_with_empty_value(self):
        "Test that key generation handles empty values"
        params = {
            'key_type': ' ',
            'key_length': 2048,
        }
        cmd = self.gpg.gen_key_input(**params)
        self.assertTrue('Key-Type: RSA\n' in cmd)
        params['key_type'] = 'DSA'
        cmd = self.gpg.gen_key_input(**params)
        self.assertTrue('Key-Type: DSA\n' in cmd)

    def test_list_keys_after_generation(self):
        "Test that after key generation, the generated key is available"
        self.test_list_keys_initial()
        self.do_key_generation()
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 1),
                        "1-element list expected")
        key_info = public_keys[0]
        fp = key_info['fingerprint']
        self.assertTrue(fp in public_keys.key_map)
        self.assertTrue(public_keys.key_map[fp] is key_info)
        for _, _, sfp in key_info['subkeys']:
            self.assertTrue(sfp in public_keys.key_map)
            self.assertTrue(public_keys.key_map[sfp] is key_info)

        # now test with sigs=True
        public_keys_sigs = self.gpg.list_keys(sigs=True)
        self.assertTrue(is_list_with_len(public_keys_sigs, 1),
                        "1-element list expected")
        key_info = public_keys_sigs[0]
        fp = key_info['fingerprint']
        self.assertTrue(fp in public_keys_sigs.key_map)
        self.assertTrue(public_keys_sigs.key_map[fp] is key_info)
        self.assertTrue(is_list_with_len(key_info['sigs'], 2))
        for siginfo in key_info['sigs']:
            self.assertTrue(len(siginfo), 3)
        for _, _, sfp in key_info['subkeys']:
            self.assertTrue(sfp in public_keys_sigs.key_map)
            self.assertTrue(public_keys_sigs.key_map[sfp] is key_info)

        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 1),
                        "1-element list expected")
        self.assertEqual(len(private_keys.fingerprints), 1)
        # Now do the same test, but using keyring and secret_keyring arguments
        pkn = 'pubring.gpg'
        skn = 'secring.gpg'
        hd = os.path.join(os.getcwd(), 'keys')
        if os.name == 'posix':
            pkn = os.path.join(hd, pkn)
            skn = os.path.join(hd, skn)
        gpg = gnupg.GPG(gnupghome=hd, gpgbinary=GPGBINARY,
                        keyring=pkn, secret_keyring=skn)
        logger.debug('Using keyring and secret_keyring arguments')
        public_keys_2 = gpg.list_keys()
        self.assertEqual(public_keys_2, public_keys)
        private_keys_2 = gpg.list_keys(secret=True)
        self.assertEqual(private_keys_2, private_keys)

        # generate additional keys so that we can test listing a subset of
        # keys
        def get_names(key_map):
            result = set()
            for info in key_map.values():
                for uid in info['uids']:
                    uid = uid.replace(' (A test user (insecure!))', '')
                    result.add(uid)
            return result

        result = self.generate_key("Charlie", "Clark", "gamma.com")
        self.assertNotEqual(None, result, "Non-null result")
        result = self.generate_key("Donna", "Davis", "delta.com")
        self.assertNotEqual(None, result, "Non-null result")
        public_keys = gpg.list_keys()
        self.assertEqual(len(public_keys), 3)
        actual = get_names(public_keys.key_map)
        expected = set(['Barbara Brown <barbara.brown@beta.com>',
                        'Charlie Clark <charlie.clark@gamma.com>',
                        'Donna Davis <donna.davis@delta.com>'])
        self.assertEqual(actual, expected)
        # specify a single key as a string
        public_keys = gpg.list_keys(keys='Donna Davis')
        actual = get_names(public_keys.key_map)
        expected = set(['Donna Davis <donna.davis@delta.com>'])
        self.assertEqual(actual, expected)
        # specify multiple keys
        public_keys = gpg.list_keys(keys=['Donna', 'Barbara'])
        actual = get_names(public_keys.key_map)
        expected = set(['Barbara Brown <barbara.brown@beta.com>',
                        'Donna Davis <donna.davis@delta.com>'])
        self.assertEqual(actual, expected)

    def test_list_signatures(self):
        logger.debug("test_list_signatures begins")
        imported = self.gpg.import_keys(SIGNED_KEYS)
        keys = self.gpg.list_keys(keys=["18897CA2"])
        self.assertTrue(is_list_with_len(keys, 1), "importing test signed key")
        sigs = self.gpg.list_keys(keys=["18897CA2"], sigs=True)[0]['sigs']
        logger.debug("testing self-signature")
        self.assertTrue(('BC6F350FB3D04076', 'Joshua Calvert (A test user) <jc@example.com>', '13x') in sigs)
        logger.debug("testing subkey self-signature")
        self.assertTrue(('BC6F350FB3D04076', 'Joshua Calvert (A test user) <jc@example.com>', '18x') in sigs)
        logger.debug("testing other signature")
        self.assertTrue(('057CCF658C074FDA', 'Winston Smith (A test user) <winston@example.com>', '10x') in sigs)
        logger.debug("test_list_signatures ends")

    def test_scan_keys(self):
        "Test that external key files can be scanned"
        expected = set([
            'Andrew Able (A test user) <andrew.able@alpha.com>',
            'Barbara Brown (A test user) <barbara.brown@beta.com>',
            'Charlie Clark (A test user) <charlie.clark@gamma.com>',
        ])
        for fn in ('test_pubring.gpg', 'test_secring.gpg'):
            data = self.gpg.scan_keys(fn)
            uids = set()
            for d in data:
                uids.add(d['uids'][0])
            self.assertEqual(uids, expected)

    def test_encryption_and_decryption(self):
        "Test that encryption and decryption works"
        logger.debug("test_encryption_and_decryption begins")
        key = self.generate_key("Andrew", "Able", "alpha.com",
                                passphrase="andy")
        andrew = key.fingerprint
        key = self.generate_key("Barbara", "Brown", "beta.com")
        barbara = key.fingerprint
        gpg = self.gpg
        gpg.encoding = 'latin-1'
        if gnupg._py3k:
            data = 'Hello, André!'
        else:
            data = unicode('Hello, André', gpg.encoding)
        data = data.encode(gpg.encoding)
        edata = str(gpg.encrypt(data, barbara))
        self.assertNotEqual(data, edata, "Data must have changed")
        ddata = gpg.decrypt(edata, passphrase="bbrown")
        if data != ddata.data:  # pragma: no cover
            logger.debug("was: %r", data)
            logger.debug("new: %r", ddata.data)
        self.assertEqual(data, ddata.data, "Round-trip must work")
        edata = str(gpg.encrypt(data, [andrew, barbara]))
        self.assertNotEqual(data, edata, "Data must have changed")
        ddata = gpg.decrypt(edata, passphrase="andy")
        self.assertEqual(data, ddata.data, "Round-trip must work")
        ddata = gpg.decrypt(edata, passphrase="bbrown")
        self.assertEqual(data, ddata.data, "Round-trip must work")
        logger.debug("test_encryption_and_decryption ends")
        # Test symmetric encryption
        data = "chippy was here"
        edata = str(gpg.encrypt(data, None, passphrase='bbrown', symmetric=True))
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(data, str(ddata))
        # Test symmetric encryption with non-default cipher
        edata = str(gpg.encrypt(data, None, passphrase='bbrown',
                    symmetric='AES256'))
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(data, str(ddata))
        # Test that you can't encrypt with no recipients
        self.assertRaises(ValueError, self.gpg.encrypt, data, [])

    def test_import_and_export(self):
        "Test that key import and export works"
        logger.debug("test_import_and_export begins")
        self.test_list_keys_initial()
        gpg = self.gpg
        result = gpg.import_keys(KEYS_TO_IMPORT)
        self.assertEqual(result.summary(), '2 imported')
        public_keys = gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 2),
                        "2-element list expected")
        private_keys = gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 0),
                        "Empty list expected")
        ascii = gpg.export_keys([k['keyid'] for k in public_keys])
        self.assertTrue(ascii.find("PGP PUBLIC KEY BLOCK") >= 0,
                        "Exported key should be public")
        ascii = ascii.replace("\r", "").strip()
        match = compare_keys(ascii, KEYS_TO_IMPORT)
        if match:  # pragma: no cover
            logger.debug("was: %r", KEYS_TO_IMPORT)
            logger.debug("now: %r", ascii)
        self.assertEqual(0, match, "Keys must match")
        #Generate a key so we can test exporting private keys
        key = self.do_key_generation()
        ascii = gpg.export_keys(key.fingerprint, True)
        self.assertTrue(isinstance(ascii, gnupg.text_type))
        self.assertTrue(ascii.find("PGP PRIVATE KEY BLOCK") >= 0,
                        "Exported key should be private")
        binary = gpg.export_keys(key.fingerprint, True, armor=False)
        self.assertFalse(isinstance(binary, gnupg.text_type))
        logger.debug("test_import_and_export ends")

    def test_import_only(self):
        "Test that key import works"
        logger.debug("test_import_only begins")
        self.test_list_keys_initial()
        self.gpg.import_keys(KEYS_TO_IMPORT)
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 2),
                        "2-element list expected")
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 0),
                        "Empty list expected")
        ascii = self.gpg.export_keys([k['keyid'] for k in public_keys])
        self.assertTrue(ascii.find("PGP PUBLIC KEY BLOCK") >= 0,
                        "Exported key should be public")
        ascii = ascii.replace("\r", "").strip()
        match = compare_keys(ascii, KEYS_TO_IMPORT)
        if match:  # pragma: no cover
            logger.debug("was: %r", KEYS_TO_IMPORT)
            logger.debug("now: %r", ascii)
        self.assertEqual(0, match, "Keys must match")
        logger.debug("test_import_only ends")

    def test_signature_verification(self):
        "Test that signing and verification works"
        logger.debug("test_signature_verification begins")
        key = self.generate_key("Andrew", "Able", "alpha.com")
        self.gpg.encoding = 'latin-1'
        if gnupg._py3k:
            data = 'Hello, André!'
        else:
            data = unicode('Hello, André', self.gpg.encoding)
        data = data.encode(self.gpg.encoding)
        sig = self.gpg.sign(data, keyid=key.fingerprint, passphrase='bbrown')
        self.assertFalse(sig, "Bad passphrase should fail")
        sig = self.gpg.sign(data, keyid=key.fingerprint, passphrase='aable')
        self.assertTrue(sig, "Good passphrase should succeed")
        self.assertTrue(sig.hash_algo)
        verified = self.gpg.verify(sig.data)
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        self.assertEqual(verified.trust_level, verified.TRUST_ULTIMATE)
        self.assertEqual(verified.trust_text, 'TRUST_ULTIMATE')
        data_file = open(self.test_fn, 'rb')
        sig = self.gpg.sign_file(data_file, keyid=key.fingerprint,
                                 passphrase='aable')
        data_file.close()
        self.assertTrue(sig, "File signing should succeed")
        self.assertTrue(sig.hash_algo)
        try:
            file = gnupg._make_binary_stream(sig.data, self.gpg.encoding)
            verified = self.gpg.verify_file(file)
        except UnicodeDecodeError:  # pragma: no cover
            # sometimes happens in Python 2.6
            from io import BytesIO
            verified = self.gpg.verify_file(BytesIO(sig.data))
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        data_file = open(self.test_fn, 'rb')
        sig = self.gpg.sign_file(data_file, keyid=key.fingerprint,
                                 passphrase='aable', detach=True)
        data_file.close()
        self.assertTrue(sig, "File signing should succeed")
        self.assertTrue(sig.hash_algo)
        try:
            file = gnupg._make_binary_stream(sig.data, self.gpg.encoding)
            verified = self.gpg.verify_file(file, self.test_fn)
        except UnicodeDecodeError:  # pragma: no cover
            # sometimes happens in Python 2.6
            from io import BytesIO
            verified = self.gpg.verify_file(BytesIO(sig.data))
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        # Test in-memory verification
        data_file = open(self.test_fn, 'rb')
        data = data_file.read()
        data_file.close()
        fd, fn = tempfile.mkstemp()
        os.write(fd, sig.data)
        os.close(fd)
        try:
            verified = self.gpg.verify_data(fn, data)
        finally:
            os.unlink(fn)
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        logger.debug("test_signature_verification ends")

    def test_signature_file(self):
        "Test that signing and verification works via the GPG output"
        logger.debug("test_signature_file begins")
        key = self.generate_key("Andrew", "Able", "alpha.com")
        data_file = open(self.test_fn, 'rb')
        sig_file = self.test_fn + '.asc'
        sig = self.gpg.sign_file(data_file, keyid=key.fingerprint,
                                 passphrase='aable', detach=True,
                                 output=sig_file)
        data_file.close()
        self.assertTrue(sig, "File signing should succeed")
        self.assertTrue(sig.hash_algo)
        self.assertTrue(os.path.exists(sig_file))
        # Test in-memory verification
        data_file = open(self.test_fn, 'rb')
        data = data_file.read()
        data_file.close()
        try:
            verified = self.gpg.verify_data(sig_file, data)
        finally:
            os.unlink(sig_file)
        if key.fingerprint != verified.fingerprint:
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        logger.debug("test_signature_file ends")

    def test_deletion(self):
        "Test that key deletion works"
        logger.debug("test_deletion begins")
        self.gpg.import_keys(KEYS_TO_IMPORT)
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 2),
                        "2-element list expected")
        self.gpg.delete_keys(public_keys[0]['fingerprint'])
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 1),
                        "1-element list expected")
        logger.debug("test_deletion ends")

    def test_nogpg(self):
        "Test that absence of gpg is handled correctly"
        self.assertRaises(OSError, gnupg.GPG, gnupghome=self.homedir,
                          gpgbinary='frob')

    def test_make_args(self):
        "Test argument line construction"
        self.gpg.options = ['--foo', '--bar']
        args = self.gpg.make_args(['a', 'b'], False)
        self.assertTrue(len(args) > 4)
        self.assertEqual(args[-4:], ['--foo', '--bar', 'a', 'b'])

    def do_file_encryption_and_decryption(self, encfname, decfname):
        "Do the actual encryption.decryptin test using given filenames"
        mode = None
        if os.name == 'posix':
            # pick a mode that won't be already in effect via umask
            if os.path.exists(encfname) and os.path.exists(decfname):
                mode = os.stat(encfname).st_mode | stat.S_IXUSR
                os.chmod(encfname, mode)
                # assume same for decfname
                os.chmod(decfname, mode)
        logger.debug('Encrypting to: %r', encfname)
        logger.debug('Decrypting to: %r', decfname)
        try:
            key = self.generate_key("Andrew", "Able", "alpha.com",
                                    passphrase="andy")
            andrew = key.fingerprint
            key = self.generate_key("Barbara", "Brown", "beta.com")
            barbara = key.fingerprint
            data = "Hello, world!"
            file = gnupg._make_binary_stream(data, self.gpg.encoding)
            edata = self.gpg.encrypt_file(file,
                                          barbara,
                                          armor=False, output=encfname)
            efile = open(encfname, 'rb')
            ddata = self.gpg.decrypt_file(efile, passphrase="bbrown",
                                          output=decfname)
            efile.seek(0, 0) # can't use os.SEEK_SET in 2.4
            edata = efile.read()
            efile.close()
            dfile = open(decfname, 'rb')
            ddata = dfile.read()
            dfile.close()
            data = data.encode(self.gpg.encoding)
            if ddata != data:  # pragma: no cover
                logger.debug("was: %r", data)
                logger.debug("new: %r", ddata)
            self.assertEqual(data, ddata, "Round-trip must work")

            # Try opening the encrypted file in text mode (Issue #39)
            # this doesn't fail in 2.x
            if gnupg._py3k:
                efile = open(encfname, 'r')
                ddata = self.gpg.decrypt_file(efile, passphrase="bbrown",
                                              output=decfname)
                self.assertFalse(ddata)
                self.assertEqual(ddata.status, "no data was provided")
                efile.close()
        finally:
            for fn in (encfname, decfname):
                if os.name == 'posix' and mode is not None:
                    # Check that the file wasn't deleted, and that the
                    # mode bits we set are still in effect
                    self.assertEqual(os.stat(fn).st_mode, mode)
                if os.path.exists(fn):
                    os.remove(fn)

    def test_file_encryption_and_decryption(self):
        "Test that encryption/decryption to/from file works"
        logger.debug("test_file_encryption_and_decryption begins")
        encfno, encfname = tempfile.mkstemp()
        decfno, decfname = tempfile.mkstemp()
        # On Windows, if the handles aren't closed, the files can't be deleted
        os.close(encfno)
        os.close(decfno)
        self.do_file_encryption_and_decryption(encfname, decfname)
        logger.debug("test_file_encryption_and_decryption ends")

    def test_filenames_with_spaces(self):       # See Issue #16
        "Test that filenames with spaces are correctly handled"
        logger.debug("test_filename_with_spaces begins")
        d = tempfile.mkdtemp()
        try:
            encfname = os.path.join(d, 'encrypted file')
            decfname = os.path.join(d, 'decrypted file')
            self.do_file_encryption_and_decryption(encfname, decfname)
        finally:
            shutil.rmtree(d)
        logger.debug("test_filename_with_spaces ends")

    def test_search_keys(self):
        "Test that searching for keys works"
        r = self.gpg.search_keys('<vinay_sajip@hotmail.com>')
        self.assertTrue(r)
        self.assertTrue('Vinay Sajip <vinay_sajip@hotmail.com>' in r[0]['uids'])
        r = self.gpg.search_keys('92905378')
        self.assertTrue(r)
        self.assertTrue('Vinay Sajip <vinay_sajip@hotmail.com>' in r[0]['uids'])

    def test_quote_with_shell(self):
        "Test shell quoting with a real shell"
        if os.name != 'posix': return

        from subprocess import PIPE, Popen

        workdir = tempfile.mkdtemp()
        try:
            s = "'\\\"; touch %s/foo #'" % workdir
            cmd = 'echo %s' % gnupg.shell_quote(s)
            p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
            p.communicate()
            self.assertEqual(p.returncode, 0)
            files = os.listdir(workdir)
            self.assertEqual(files, [])
            fn = "'ab?'"
            cmd = 'touch %s/%s' % (workdir, gnupg.shell_quote(fn))
            p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
            p.communicate()
            self.assertEqual(p.returncode, 0)
            files = os.listdir(workdir)
            self.assertEqual(files, ["'ab?'"])
        finally:
            shutil.rmtree(workdir)

    def disabled_test_signing_with_uid(self):  # pragma: no cover
        "Test that signing with uids works. On hold for now."
        logger.debug("test_signing_with_uid begins")
        key = self.generate_key("Andrew", "Able", "alpha.com")
        uid = self.gpg.list_keys(True)[-1]['uids'][0]
        try:
            signfile = open(self.test_fn,'rb')
            signed = self.gpg.sign_file(signfile, keyid=uid,
                                        passphrase='aable',
                                        detach=True)
        finally:
            signfile.close()
        self.assertTrue(signed.data)
        logger.debug("test_signing_with_uid ends")

TEST_GROUPS = {
    'sign' : set(['test_signature_verification']),
    'crypt' : set(['test_encryption_and_decryption',
                   'test_file_encryption_and_decryption',
                   'test_filenames_with_spaces']),
    'key' : set(['test_deletion', 'test_import_and_export',
                 'test_list_keys_after_generation',
                 'test_list_signatures',
                 'test_key_generation_with_invalid_key_type',
                 'test_key_generation_with_escapes',
                 'test_key_generation_with_empty_value',
                 'test_key_generation_with_colons',
                 'test_search_keys', 'test_scan_keys']),
    'import' : set(['test_import_only']),
    'basic' : set(['test_environment', 'test_list_keys_initial',
                   'test_nogpg', 'test_make_args',
                   'test_quote_with_shell']),
    'test': set(['test_search_keys']),
}

def suite(args=None):
    if args is None:
        args = sys.argv[1:]
    if not args or args == ['--no-doctests']:
        result = unittest.TestLoader().loadTestsFromTestCase(GPGTestCase)
        want_doctests = not args
    else:  # pragma: no cover
        tests = set()
        want_doctests = False
        for arg in args:
            if arg in TEST_GROUPS:
                tests.update(TEST_GROUPS[arg])
            elif arg == "doc":
                want_doctests = True
            else:
                print("Ignoring unknown test group %r" % arg)
        result = unittest.TestSuite(list(map(GPGTestCase, tests)))
    if want_doctests:
        result.addTest(doctest.DocTestSuite(gnupg))
    return result

def init_logging():
    logging.basicConfig(level=logging.DEBUG, filename="test_gnupg.log",
                        filemode="w", format="%(asctime)s %(levelname)-5s %(name)-10s %(threadName)-10s %(lineno)4d %(message)s")

def main():
    init_logging()
    tests = suite()
    results = unittest.TextTestRunner(verbosity=2).run(tests)
    return not results.wasSuccessful()


if __name__ == "__main__":
    sys.exit(main())
