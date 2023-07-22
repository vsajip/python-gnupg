# -*- coding: utf-8 -*-
"""
A test harness for gnupg.py.

Copyright (C) 2008-2023 Vinay Sajip. All rights reserved.
"""
import argparse
import json
import logging
import os.path
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest

try:
    unicode
except NameError:
    unicode = str

try:
    from unittest import skipIf
except ImportError:  # pragma: no cover
    # For now, for Python < 2.7
    def skipIf(condition, message):
        if not condition:
            return lambda x: x
        else:
            return lambda x: None


import gnupg

__author__ = 'Vinay Sajip'
__date__ = '$22-Jul-2023 16:37:02$'

ALL_TESTS = True

gnupg.log_everything = True

logger = logging.getLogger(__name__)

GPGBINARY = os.environ.get('GPGBINARY', 'gpg')

KEYS_TO_IMPORT = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (MingW32)

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
=sqld
-----END PGP PUBLIC KEY BLOCK-----"""

SIGNED_KEYS = """-----BEGIN PGP PUBLIC KEY BLOCK-----
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

SECRET_KEY = """
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQPGBFztd1UBCACiHhlEJIGfXNEiUX4GwamgdLOkJ3mbn5OyV4M/Ie3YvvHxveq/
TFYbuV63iuDVhNXpDUNmGsTq4vFaMsseLl7eESw8UTa3XklHHjh56kw0AVkJA75A
Xq/VshFobLNxYZdtlOVkKe1a3uJVKs+BqFjhavEjQyhkpWvBY51OzCSc2AN/aQZA
F3AltZ8luIHZPs8zVbgH90WIpze+vzAd9FyXD0wV6gylGSifHj8zIhac80evQgD9
50De7EPnSdgZSNwnlrhQtAIB5UnTETxXk34/W0Rq+BKn6SuchtaP7hXIHC0+B0C7
zBzPYKMQ7vXc/hceNwSGtgovhaQPCcv1byFBABEBAAH+BwMCUNdAVY/RMdJg1q5n
FQOyVZl2tvd3krExjGYvhabwijbPz+TrVkPhKqdkp4Hbf3oXV/bcbQhG2dld4Ooc
+xtEpTqYw08bNDuk4NEAvggasUkgssHZccDmHySGfA9U8C7B0Hj8xT4SifnuVNL+
xp9iv1BS03s+UIEVZ2rGjDQy7/G/U6/ZpLqFg+C113VQs6yz0VMsnnAQOMgN0+gQ
aZb6VNPR7nZ5+/hRlx0DgXu++lei9HTmHRz+ZvbbYjeU9nj10eANhO0lEvlgtyXa
v4Y5ERwk86gbkSRGtN88qVK/+GXK60Q33EoGMlwPZrfFGx+N5QuPEnCjT1vvz7E3
HhCpe4u5Idusgui+tDkxq8BEz6iTGMO1hcb75MDdIQBhJzeJ7OIxyBfqLReF4+Ut
eNwy0wpN3xuEeYvP4ZIe7hj74WWIuKq2+lesPm4eWRPoaQ5MZXmEwbjr29e++V7D
EkHgCYio6TVwrHA0LRSNfm8VVBV2cdsqFOLLutudHoC8BnjetEetmYaA99u0Pevz
NscYwfaWLNW/d5FGyPUb+GQFYzmQWUfUzpg9hu7U79uA0kOwC+4nK6LEalILtoHn
YO3PvvcCEnpWBlDhCR3n0zkNQCulvQKS/ww5q/MDNqvibKiMJHJ1xP89tEU3lnHl
qgwHVmleqUR+yzdg5lo96Yey5yaDdhK5ZR1TFC4qK4Igcn2+WG109659bJUGpEre
Vktu530JutX38ZoyKdHO0uPs/ft/hgBhNd6MKmh7eejo84Wn6/lxkfMydkfKm5QY
dMHF3Ew+l7aACAs3l95V0YDNzA0FyOFkb/tqxyx8dP+O2NdZQZSvG+yxDav05bCq
kwz+7H7sJnUj1JJtUgPTL9yVH+LyUhL8AU13UKVjBFJ4VL5+KDD9KwPkk6aN7zDW
Qv0g8Cc7A8H0tB5BdXRvZ2VuZXJhdGVkIEtleSA8dXNlcjFAdGVzdD6JATgEEwEI
ACIFAlztd1UCGy8GCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEGP32fXSIJgg
IXgH/3o1rUzbjjz1sMoBwRv4qLmgeqlB2YJSVzLWOn4AcrHbxup5O9nJkqG+YFwH
OFmytuiPDKmA4ZXww8f+2rHXdDuwI5SWnfhuPpV863BulIhtjwiwqD9eIzQ9LX79
K7hXRJ4I0AkYEbDHOWlLHZCrjul/ZaS10QRVR21EYICha2I8tvxsRMPp0I93XnuB
T+z7ykRxRjpMv6MfhWVcw5B0s7lPedLhcx657HfY49t36/CIZ9/zMKsduX7cTOAh
tO8f06R3yfjxLRD8y89frVP3+tGMvt2yGOd5TT0zht5yYcG6QkiHlfdgXqeE8nsU
2392Xn/RETq6xCj3kG6K3wbWqh0=
=2A5s
-----END PGP PRIVATE KEY BLOCK-----
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


AGENT_CONFIG = '''allow-loopback-pinentry
log-file socket:///tmp/S.my-gnupg-log
verbose
debug ipc
'''

ENABLE_TOFU = 'ENABLE_TOFU' in os.environ

if ENABLE_TOFU:  # pragma: no cover
    GPG_CONFIG = 'trust-model tofu+pgp\ntofu-default-policy unknown\n'


def prepare_homedir(hd):
    if not os.path.isdir(hd):  # pragma: no cover
        os.makedirs(hd)
    os.chmod(hd, 0x1C0)
    fn = os.path.join(hd, 'gpg-agent.conf')
    with open(fn, 'w') as f:
        f.write(AGENT_CONFIG)
    if ENABLE_TOFU:  # pragma: no cover
        fn = os.path.join(hd, 'gpg.conf')
        with open(fn, 'w') as f:
            f.write(GPG_CONFIG)


class GPGTestCase(unittest.TestCase):

    def setUp(self):
        ident = self.id().rsplit('.', 1)[-1]
        logger.debug('-- %s starting ---------------------------' % ident)
        if 'STATIC_TEST_HOMEDIR' not in os.environ:
            hd = tempfile.mkdtemp(prefix='keys-')
        else:  # pragma: no cover
            hd = os.path.join(os.getcwd(), 'keys')
            if os.path.exists(hd):
                self.assertTrue(os.path.isdir(hd), 'Not a directory: %s' % hd)
                shutil.rmtree(hd, ignore_errors=True)
        prepare_homedir(hd)
        self.homedir = hd
        self.gpg = gpg = gnupg.GPG(gnupghome=hd, gpgbinary=GPGBINARY)
        v = gpg.version
        if v:
            if v >= (2, ):  # pragma: no cover
                gpg.options = ['--debug-quick-random']
            else:
                gpg.options = ['--quick-random']
        self.test_fn = test_fn = 'random_binary_data'
        if not os.path.exists(test_fn):  # pragma: no cover
            data_file = open(test_fn, 'wb')
            data_file.write(os.urandom(5120 * 1024))
            data_file.close()

    def tearDown(self):
        if 'STATIC_TEST_HOMEDIR' not in os.environ:
            shutil.rmtree(self.homedir, ignore_errors=True)
        ident = self.id().rsplit('.', 1)[-1]
        logger.debug('-- %s finished ---------------------------' % ident)

    def test_environment(self):
        "Test the environment by ensuring that setup worked"
        hd = self.homedir
        self.assertTrue(os.path.exists(hd) and os.path.isdir(hd), 'Not an existing directory: %s' % hd)

    def test_list_keys_initial(self):
        "Test that initially there are no keys"
        public_keys = self.gpg.list_keys()
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 0), 'Empty list expected')
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 0), 'Empty list expected')

    def generate_key(self, first_name, last_name, domain, passphrase=None, with_subkey=True):
        "Generate a key"
        params = {
            'Key-Type': 'DSA',
            'Key-Length': 1024,
            'Name-Comment': 'A test user',
            'Expire-Date': 0,
        }
        if with_subkey:
            params['Subkey-Type'] = 'ELG-E'
            params['Subkey-Length'] = 2048

        options = self.gpg.options or []
        if '--debug-quick-random' in options or '--quick-random' in options:
            # If using the fake RNG, a key isn't regarded as valid
            # unless its comment has the text (insecure!) in it.
            params['Name-Comment'] = 'A test user (insecure!)'
        params['Name-Real'] = '%s %s' % (first_name, last_name)
        params['Name-Email'] = ('%s.%s@%s' % (first_name, last_name, domain)).lower()
        if passphrase is None:
            passphrase = ('%s%s' % (first_name[0], last_name)).lower()
        params['Passphrase'] = passphrase
        cmd = self.gpg.gen_key_input(**params)
        return self.gpg.gen_key(cmd)

    def do_key_generation(self):
        "Test that key generation succeeds"
        result = self.generate_key('Barbara', 'Brown', 'beta.com')
        self.assertNotEqual(None, result, 'Non-null result')
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
        self.assertFalse(result.fingerprint, 'Null fingerprint result')
        self.assertEqual(2, result.returncode, 'Unexpected return code')

    def test_key_generation_with_colons(self):
        "Test that key generation handles colons in key fields"
        params = {
            'key_type': 'RSA',
            'name_real': 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19',
            'name_comment': 'dummy comment',
            'name_email': 'test.name@example.com',
        }
        if self.gpg.version >= (2, 1):
            params['passphrase'] = 'foo'
        cmd = self.gpg.gen_key_input(**params)
        result = self.gpg.gen_key(cmd)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        keys = self.gpg.list_keys()
        self.assertEqual(0, keys.returncode, 'Non-zero return code')
        self.assertEqual(len(keys), 1)
        key = keys[0]
        uids = key['uids']
        self.assertEqual(len(uids), 1)
        uid = uids[0]
        self.assertEqual(uid, 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19 '
                         '(dummy comment) <test.name@example.com>')

    def test_key_generation_with_escapes(self):
        "Test that key generation handles escape characters"
        params = {
            'name_real': 'Test Name',
            'name_comment': 'Funny chars: \\r\\n\\f\\v\\0\\b',
            'name_email': 'test.name@example.com',
        }
        if self.gpg.version >= (2, 1):
            params['passphrase'] = 'foo'
        cmd = self.gpg.gen_key_input(**params)
        result = self.gpg.gen_key(cmd)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        keys = self.gpg.list_keys()
        self.assertEqual(0, keys.returncode, 'Non-zero return code')
        self.assertEqual(len(keys), 1)
        key = keys[0]
        uids = key['uids']
        self.assertEqual(len(uids), 1)
        uid = uids[0]
        self.assertEqual(uid, 'Test Name (Funny chars: '
                         '\r\n\x0c\x0b\x00\x08) <test.name@example.com>')

    @unittest.skipIf(os.name == 'nt', 'Test requires POSIX-style permissions')
    def test_key_generation_failure(self):
        if self.gpg.version < (2, 0):  # pragma: no cover
            raise unittest.SkipTest('gpg 1.x hangs in this test')
        if not os.path.exists('rokeys'):  # pragma: no cover
            os.mkdir('rokeys')
        os.chmod('rokeys', 0o400)  # no one can write/search this directory
        gpg = gnupg.GPG(gnupghome='rokeys', gpgbinary=GPGBINARY)
        params = {
            'Key-Type': 'RSA',
            'Key-Length': 1024,
            'Subkey-Type': 'ELG-E',
            'Subkey-Length': 2048,
            'Name-Comment': 'A test user',
            'Expire-Date': 0,
            'Name-Real': 'Test Name',
            'Name-Email': 'test.name@example.com',
        }
        cmd = gpg.gen_key_input(**params)
        result = gpg.gen_key(cmd)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.status, 'key not created')

    def test_key_generation_input(self):
        "Test that key generation input handles empty values, curves etc."
        params = {
            'key_type': ' ',
            'key_length': 2048,
        }
        cmd = self.gpg.gen_key_input(**params)
        self.assertTrue('Key-Type: RSA\n' in cmd)
        params['key_type'] = 'DSA'
        cmd = self.gpg.gen_key_input(**params)
        self.assertTrue('Key-Type: DSA\n' in cmd)
        params = {
            'key_type': 'ECDSA',
            'key_curve': 'nistp384',
            'subkey_type': 'ECDH',
            'subkey_curve': 'nistp384',
            'name_comment': 'NIST P-384',
        }
        cmd = self.gpg.gen_key_input(**params)
        for s in ('Key-Type: ECDSA', 'Key-Curve: nistp384', 'Subkey-Type: ECDH', 'Subkey-Curve: nistp384',
                  'Name-Comment: NIST P-384'):
            self.assertTrue('%s\n' % s in cmd)
        self.assertFalse('Key-Length: ' in cmd)

    def test_add_subkey(self):
        "Test that subkeys can be added"
        if self.gpg.version[0] < 2:  # pragma: no cover
            raise unittest.SkipTest('Feature unavailable in GnuPG 1.x')
        master_key = self.generate_key('Charlie', 'Clark', 'gamma.com', passphrase='123', with_subkey=False)
        self.assertEqual(0, master_key.returncode, 'Non-zero return code')

        result = self.gpg.add_subkey(master_key=master_key.fingerprint,
                                     master_passphrase='123',
                                     algorithm='dsa',
                                     usage='sign',
                                     expire=0)
        self.assertEqual(0, result.returncode, 'Non-zero return code')

    def test_add_subkey_with_invalid_key_type(self):
        "Test that subkey generation handles invalid key type"
        if self.gpg.version[0] < 2:  # pragma: no cover
            raise unittest.SkipTest('Feature unavailable in GnuPG 1.x')
        master_key = self.generate_key('Charlie', 'Clark', 'gamma.com', passphrase='123', with_subkey=False)
        self.assertEqual(0, master_key.returncode, 'Non-zero return code')

        result = self.gpg.add_subkey(master_key=master_key.fingerprint,
                                     master_passphrase='123',
                                     algorithm='INVALID',
                                     usage='sign',
                                     expire=0)

        self.assertFalse(result.data, 'Null data result')
        self.assertEqual('', result.fingerprint, 'Empty fingerprint result')
        self.assertEqual(2, result.returncode, 'Unexpected return code')

    def test_deletion_subkey(self):
        "Test that subkey deletion works"
        if self.gpg.version[0] < 2:  # pragma: no cover
            raise unittest.SkipTest('Feature unavailable in GnuPG 1.x')
        master_key = self.generate_key('Charlie', 'Clark', 'gamma.com', passphrase='123', with_subkey=False)
        self.assertEqual(0, master_key.returncode, 'Non-zero return code')

        subkey = self.gpg.add_subkey(master_key=master_key.fingerprint,
                                     master_passphrase='123',
                                     algorithm='dsa',
                                     usage='sign',
                                     expire=0)
        self.assertEqual(0, subkey.returncode, 'Non-zero return code')

        public_keys = self.gpg.list_keys()
        key_info = public_keys[0]

        private_keys = self.gpg.list_keys(secret=True)
        secret_key_info = private_keys[0]

        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 1), '1-element list expected')
        self.assertEqual(len(key_info['subkeys']), 1, '1-element list expected')

        self.assertTrue(is_list_with_len(private_keys, 1), '1-element list expected')
        self.assertEqual(len(secret_key_info['subkeys']), 1, '1-element list expected')
        result = self.gpg.delete_keys(subkey.fingerprint, secret=True, passphrase='123', exclamation_mode=True)
        result = self.gpg.delete_keys(subkey.fingerprint, exclamation_mode=True)
        self.assertEqual(0, result.returncode, 'Non-zero return code')

        public_keys = self.gpg.list_keys()
        key_info = public_keys[0]

        private_keys = self.gpg.list_keys(secret=True)
        secret_key_info = private_keys[0]

        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 1), '1-element list expected')
        self.assertEqual(len(key_info['subkeys']), 0, '0-element list expected')

        self.assertTrue(is_list_with_len(private_keys, 1), '1-element list expected')
        self.assertEqual(len(secret_key_info['subkeys']), 0, '1-element list expected')

    def test_list_subkey_after_generation(self):
        "Test that after subkey generation, the generated subkey is available"
        if self.gpg.version[0] < 2:  # pragma: no cover
            raise unittest.SkipTest('Feature unavailable in GnuPG 1.x')
        self.test_list_keys_initial()

        master_key = self.generate_key('Charlie', 'Clark', 'gamma.com', passphrase='123', with_subkey=False)
        self.assertEqual(0, master_key.returncode, 'Non-zero return code')

        subkey_sign = self.gpg.add_subkey(master_key=master_key.fingerprint,
                                          master_passphrase='123',
                                          algorithm='dsa',
                                          usage='sign',
                                          expire=0)
        self.assertEqual(0, subkey_sign.returncode, 'Non-zero return code')

        subkey_encrypt = self.gpg.add_subkey(master_key=master_key.fingerprint,
                                             master_passphrase='123',
                                             algorithm='rsa',
                                             usage='encrypt',
                                             expire=0)
        self.assertEqual(0, subkey_encrypt.returncode, 'Non-zero return code')

        public_keys = self.gpg.list_keys()
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 1), '1-element list expected')
        key_info = public_keys[0]
        if self.gpg.version >= (2, 1):
            self.assertTrue(key_info['keygrip'])
        fp = key_info['fingerprint']
        self.assertTrue(fp in public_keys.key_map)
        self.assertTrue(public_keys.key_map[fp] is key_info)
        self.assertEqual(fp, master_key.fingerprint)
        self.assertTrue('subkey_info' in key_info)
        skinfo = key_info['subkey_info']
        self.assertEqual(len(skinfo), 2)
        self.assertEqual(key_info['subkeys'][0][1], 's')
        self.assertEqual(key_info['subkeys'][0][2], subkey_sign.fingerprint)

        self.assertEqual(key_info['subkeys'][1][1], 'e')
        self.assertEqual(key_info['subkeys'][1][2], subkey_encrypt.fingerprint)
        for skid, _, sfp, grp in key_info['subkeys']:
            self.assertTrue(skid in skinfo)
            info = skinfo[skid]
            self.assertEqual(info['keyid'], skid)
            self.assertEqual(info['type'], 'sub')
            self.assertTrue(sfp in public_keys.key_map)
            self.assertTrue(public_keys.key_map[sfp] is key_info)
            if self.gpg.version >= (2, 1):
                self.assertTrue(grp)

    def test_list_keys_after_generation(self):
        "Test that after key generation, the generated key is available"
        self.test_list_keys_initial()
        self.do_key_generation()
        public_keys = self.gpg.list_keys()
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 1), '1-element list expected')
        key_info = public_keys[0]
        if self.gpg.version >= (2, 1):
            self.assertTrue(key_info['keygrip'])
        fp = key_info['fingerprint']
        self.assertTrue(fp in public_keys.key_map)
        self.assertTrue(public_keys.key_map[fp] is key_info)
        self.assertTrue('subkey_info' in key_info)
        skinfo = key_info['subkey_info']
        for skid, _, sfp, grp in key_info['subkeys']:
            self.assertTrue(skid in skinfo)
            info = skinfo[skid]
            self.assertEqual(info['keyid'], skid)
            self.assertEqual(info['type'], 'sub')
            self.assertTrue(sfp in public_keys.key_map)
            self.assertTrue(public_keys.key_map[sfp] is key_info)
            if self.gpg.version >= (2, 1):
                self.assertTrue(grp)

        # now test with sigs=True
        public_keys_sigs = self.gpg.list_keys(sigs=True)
        self.assertEqual(0, public_keys_sigs.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys_sigs, 1), '1-element list expected')
        key_info = public_keys_sigs[0]
        if self.gpg.version >= (2, 1):
            self.assertTrue(key_info['keygrip'])
        fp = key_info['fingerprint']
        self.assertTrue(fp in public_keys_sigs.key_map)
        self.assertTrue(public_keys_sigs.key_map[fp] is key_info)
        self.assertTrue(is_list_with_len(key_info['sigs'], 2))
        self.assertTrue('subkey_info' in key_info)
        skinfo = key_info['subkey_info']
        for siginfo in key_info['sigs']:
            self.assertTrue(len(siginfo), 3)
        for skid, _, sfp, grp in key_info['subkeys']:
            self.assertTrue(skid in skinfo)
            info = skinfo[skid]
            self.assertEqual(info['keyid'], skid)
            self.assertEqual(info['type'], 'sub')
            self.assertTrue(sfp in public_keys_sigs.key_map)
            self.assertTrue(public_keys_sigs.key_map[sfp] is key_info)
            if self.gpg.version >= (2, 1):
                self.assertTrue(grp)

        private_keys = self.gpg.list_keys(secret=True)
        self.assertEqual(0, private_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(private_keys, 1), '1-element list expected')
        self.assertEqual(len(private_keys.fingerprints), 1)
        key_info = private_keys[0]
        if self.gpg.version >= (2, 1):
            self.assertTrue(key_info['keygrip'])
        self.assertTrue('subkey_info' in key_info)
        skinfo = key_info['subkey_info']
        self.assertTrue(skid in skinfo)
        info = skinfo[skid]
        self.assertEqual(info['keyid'], skid)
        self.assertEqual(info['type'], 'ssb')

        # Now do the same test, but using keyring and secret_keyring arguments
        if self.gpg.version < (2, 1):  # pragma: no cover
            pkn = 'pubring.gpg'
            skn = 'secring.gpg'
        else:
            # On GnuPG >= 2.1, --secret-keyring is obsolete and ignored,
            # and the keyring file name has changed.
            pkn = 'pubring.kbx'
            skn = None
        hd = self.homedir
        if os.name == 'posix':
            pkn = os.path.join(hd, pkn)
            if skn:  # pragma: no cover
                skn = os.path.join(hd, skn)
        gpg = gnupg.GPG(gnupghome=hd, gpgbinary=GPGBINARY, keyring=pkn, secret_keyring=skn)
        logger.debug('Using keyring and secret_keyring arguments')
        public_keys_2 = gpg.list_keys()
        self.assertEqual(0, public_keys_2.returncode, 'Non-zero return code')
        self.assertEqual(public_keys_2, public_keys)
        private_keys_2 = gpg.list_keys(secret=True)
        self.assertEqual(0, private_keys_2.returncode, 'Non-zero return code')
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

        result = self.generate_key('Charlie', 'Clark', 'gamma.com')
        self.assertNotEqual(None, result, 'Non-null result')
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        result = self.generate_key('Donna', 'Davis', 'delta.com')
        self.assertNotEqual(None, result, 'Non-null result')
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        public_keys = gpg.list_keys()
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertEqual(len(public_keys), 3)
        actual = get_names(public_keys.key_map)
        expected = set([
            'Barbara Brown <barbara.brown@beta.com>', 'Charlie Clark <charlie.clark@gamma.com>',
            'Donna Davis <donna.davis@delta.com>'
        ])
        self.assertEqual(actual, expected)
        # specify a single key as a string
        public_keys = gpg.list_keys(keys='Donna Davis')
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        actual = get_names(public_keys.key_map)
        expected = set(['Donna Davis <donna.davis@delta.com>'])
        self.assertEqual(actual, expected)
        # specify multiple keys
        public_keys = gpg.list_keys(keys=['Donna', 'Barbara'])
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        actual = get_names(public_keys.key_map)
        expected = set(['Barbara Brown <barbara.brown@beta.com>', 'Donna Davis <donna.davis@delta.com>'])
        self.assertEqual(actual, expected)

    def test_key_trust(self):
        "Test that trusting keys works"
        gpg = self.gpg
        result = gpg.import_keys(KEYS_TO_IMPORT)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        keys = gpg.list_keys()
        self.assertEqual(0, keys.returncode, 'Non-zero return code')
        fingerprints = []
        for key in keys:
            self.assertEqual(key['ownertrust'], '-')
            fingerprints.append(key['fingerprint'])
        cases = (
            ('TRUST_NEVER', 'n'),
            ('TRUST_MARGINAL', 'm'),
            ('TRUST_FULLY', 'f'),
            ('TRUST_ULTIMATE', 'u'),
            ('TRUST_UNDEFINED', 'q'),
            ('TRUST_EXPIRED', 'e'),
        )
        for param, expected in cases:
            gpg.trust_keys(fingerprints, param)
            keys = gpg.list_keys(keys=fingerprints)
            for key in keys:
                self.assertEqual(key['ownertrust'], expected)
        self.assertRaises(ValueError, gpg.trust_keys, fingerprints, 'TRUST_FOOBAR')
        self.assertRaises(ValueError, gpg.trust_keys, 'NO_SUCH_FINGERPRINT', 'TRUST_NEVER')
        # gpg should raise an error for the following - but it doesn't!
        # self.assertRaises(ValueError, gpg.trust_keys,
        #                   'BADF00DBADF00DBADF00DBADF00DBADF00DBADF0',
        #                   'TRUST_NEVER')

    def test_list_signatures(self):
        imported = self.gpg.import_keys(SIGNED_KEYS)
        self.assertEqual(0, imported.returncode, 'Non-zero return code')
        keys = self.gpg.list_keys(keys=['18897CA2'])
        self.assertEqual(0, keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(keys, 1), 'importing test signed key')
        sigs = self.gpg.list_keys(keys=['18897CA2'], sigs=True)[0]['sigs']
        logger.debug('testing self-signature')
        self.assertTrue(('BC6F350FB3D04076', 'Joshua Calvert (A test user) <jc@example.com>', '13x') in sigs)
        logger.debug('testing subkey self-signature')
        self.assertTrue(('BC6F350FB3D04076', 'Joshua Calvert (A test user) <jc@example.com>', '18x') in sigs)
        logger.debug('testing other signature')
        self.assertTrue(('057CCF658C074FDA', 'Winston Smith (A test user) <winston@example.com>', '10x') in sigs)

    def test_scan_keys(self):
        "Test that external key files can be scanned"
        # Don't use SkipTest for now, as not available for Python < 2.7
        if self.gpg.version < (2, 1):  # pragma: no cover
            expected = set([
                'Andrew Able (A test user) <andrew.able@alpha.com>',
                'Barbara Brown (A test user) <barbara.brown@beta.com>',
                'Charlie Clark (A test user) <charlie.clark@gamma.com>',
            ])
            test_files = ('test_pubring.gpg', 'test_secring.gpg')
            key_fn = None
        else:
            expected = set([
                'Gary Gross (A test user) <gary.gross@gamma.com>',
                'Danny Davis (A test user) <danny.davis@delta.com>',
            ])
            fd, key_fn = tempfile.mkstemp(prefix='pygpg-test-')
            os.write(fd, KEYS_TO_IMPORT.encode('ascii'))
            os.close(fd)
            test_files = (key_fn, )
        try:
            for fn in test_files:
                logger.debug('scanning keys in %s', fn)
                data = self.gpg.scan_keys(fn)
                self.assertEqual(0, data.returncode, 'Non-zero return code')
                uids = set()
                for d in data:
                    uids.add(d['uids'][0])
                self.assertEqual(uids, expected)
        finally:
            if key_fn:
                os.remove(key_fn)

    def test_scan_keys_mem(self):
        "Test that external keys in memory can be scanned"
        expected = set([
            'Gary Gross (A test user) <gary.gross@gamma.com>',
            'Danny Davis (A test user) <danny.davis@delta.com>',
        ])
        for key in (KEYS_TO_IMPORT, ):
            logger.debug('testing scan_keys')
            data = self.gpg.scan_keys_mem(key)
            self.assertEqual(0, data.returncode, 'Non-zero return code')
            uids = set()
            for d in data:
                uids.add(d['uids'][0])
            self.assertEqual(uids, expected)

    def test_encryption_and_decryption(self):
        "Test that encryption and decryption works"
        key = self.generate_key('Andrew', 'Able', 'alpha.com', passphrase='andy')
        self.assertEqual(0, key.returncode, 'Non-zero return code')
        andrew = key.fingerprint
        key = self.generate_key('Barbara', 'Brown', 'beta.com')
        self.assertEqual(0, key.returncode, 'Non-zero return code')
        barbara = key.fingerprint
        gpg = self.gpg
        if gnupg._py3k:
            data = 'Hello, André!'
        else:  # pragma: no cover
            data = unicode('Hello, André', gpg.encoding)
        data = data.encode(gpg.encoding)
        result = gpg.encrypt(data, barbara)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        edata = str(result)
        self.assertNotEqual(data, edata, 'Data must have changed')
        self.assertRaises(ValueError, gpg.decrypt, edata, passphrase='bbr\x00own')
        self.assertRaises(ValueError, gpg.decrypt, edata, passphrase='bbr\rown')
        self.assertRaises(ValueError, gpg.decrypt, edata, passphrase='bbr\nown')
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(0, ddata.returncode, 'Non-zero return code')
        if data != ddata.data:  # pragma: no cover
            logger.debug('was: %r', data)
            logger.debug('new: %r', ddata.data)
        self.assertEqual(data, ddata.data, 'Round-trip must work')
        result = gpg.encrypt(data, [andrew, barbara])
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        edata = str(result)
        self.assertNotEqual(data, edata, 'Data must have changed')
        ddata = gpg.decrypt(edata, passphrase='andy')
        self.assertEqual(0, ddata.returncode, 'Non-zero return code')
        self.assertEqual(data, ddata.data, 'Round-trip must work')
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(data, ddata.data, 'Round-trip must work')
        # Test symmetric encryption
        data = 'chippy was here'
        self.assertRaises(ValueError, gpg.encrypt, data, None, passphrase='bbr\x00own', symmetric=True)
        self.assertRaises(ValueError, gpg.encrypt, data, None, passphrase='bbr\rown', symmetric=True)
        self.assertRaises(ValueError, gpg.encrypt, data, None, passphrase='bbr\nown', symmetric=True)
        result = gpg.encrypt(data, None, passphrase='bbrown', symmetric=True)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        edata = str(result)
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(0, ddata.returncode, 'Non-zero return code')
        self.assertEqual(data, str(ddata))
        # Test symmetric encryption with non-default cipher
        result = gpg.encrypt(data, None, passphrase='bbrown', symmetric='AES256')
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        edata = str(result)
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(0, ddata.returncode, 'Non-zero return code')
        self.assertEqual(data, str(ddata))
        # Test that you can't encrypt with no recipients
        self.assertRaises(ValueError, self.gpg.encrypt, data, [])
        # Test extra_args parameter
        result = gpg.encrypt(data, barbara, extra_args=['-z', '0'])
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        edata = str(result)
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(data.encode('ascii'), ddata.data, 'Round-trip must work')
        # Test on_data functionality

        chunks = []

        def collector(data):
            chunks.append(data)

        gpg.on_data = collector
        result = gpg.encrypt(data, barbara)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        edata = str(result)
        self.assertTrue(chunks)
        expected = type(chunks[0])().join(chunks)
        self.assertEqual(expected.decode('ascii'), edata)
        chunks = []
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(0, ddata.returncode, 'Non-zero return code')
        self.assertEqual(data.encode('ascii'), ddata.data, 'Round-trip must work')
        expected = type(chunks[0])().join(chunks)
        self.assertEqual(expected.decode('ascii'), data)

        # test signing with encryption and verification during decryption
        logger.debug('encrypting with signature')
        gpg.on_data = None
        result = gpg.encrypt(data, barbara, sign=andrew, passphrase='andy')
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        edata = str(result)
        logger.debug('decrypting with verification')
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(0, ddata.returncode, 'Non-zero return code')
        self.assertEqual(data.encode('ascii'), ddata.data, 'Round-trip must work')
        sig_values = list(ddata.sig_info.values())
        self.assertTrue(sig_values)
        sig_info = sig_values[0]
        self.assertEqual(sig_info['fingerprint'], andrew)
        logger.debug('decrypting with verification succeeded')

    def test_import_and_export(self):
        "Test that key import and export works"
        self.test_list_keys_initial()
        gpg = self.gpg
        result = gpg.import_keys(KEYS_TO_IMPORT)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        self.assertTrue(bool(result))
        self.assertEqual(result.summary(), '2 imported')
        public_keys = gpg.list_keys()
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 2), '2-element list expected')
        private_keys = gpg.list_keys(secret=True)
        self.assertEqual(0, private_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(private_keys, 0), 'Empty list expected')
        ascii = gpg.export_keys([k['keyid'] for k in public_keys])
        self.assertTrue(ascii.find('PGP PUBLIC KEY BLOCK') >= 0, 'Exported key should be public')
        ascii = ascii.replace('\r', '').strip()
        match = compare_keys(ascii, KEYS_TO_IMPORT)
        if match:  # pragma: no cover
            logger.debug('was: %r', KEYS_TO_IMPORT)
            logger.debug('now: %r', ascii)
        self.assertEqual(0, match, 'Keys must match')
        # Generate a key so we can test exporting private keys
        key = self.do_key_generation()
        if self.gpg.version < (2, 1):  # pragma: no cover
            passphrase = None
        else:
            passphrase = 'bbrown'
        ascii = gpg.export_keys(key.fingerprint, True, passphrase=passphrase)
        self.assertTrue(isinstance(ascii, gnupg.text_type))
        self.assertTrue(ascii.find('PGP PRIVATE KEY BLOCK') >= 0, 'Exported key should be private')
        binary = gpg.export_keys(key.fingerprint, True, armor=False, passphrase=passphrase)
        self.assertFalse(isinstance(binary, gnupg.text_type))
        # import a secret key, and confirm that it's found in the list of
        # secret keys.
        result = gpg.import_keys(SECRET_KEY)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        self.assertEqual(result.summary(), '1 imported')
        private_keys = gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 2))
        found = False
        for pk in private_keys:
            if pk['keyid'].endswith('D2209820'):
                found = True
                break
        self.assertTrue(found)
        self.assertEqual(pk['uids'][0], 'Autogenerated Key <user1@test>')

    def test_import_only(self):
        "Test that key import works"
        self.test_list_keys_initial()
        result = self.gpg.import_keys(KEYS_TO_IMPORT)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        public_keys = self.gpg.list_keys()
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 2), '2-element list expected')
        private_keys = self.gpg.list_keys(secret=True)
        self.assertEqual(0, private_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(private_keys, 0), 'Empty list expected')
        ascii = self.gpg.export_keys([k['keyid'] for k in public_keys])
        self.assertTrue(ascii.find('PGP PUBLIC KEY BLOCK') >= 0, 'Exported key should be public')
        ascii = ascii.replace('\r', '').strip()
        match = compare_keys(ascii, KEYS_TO_IMPORT)
        if match:  # pragma: no cover
            logger.debug('was: %r', KEYS_TO_IMPORT)
            logger.debug('now: %r', ascii)
        self.assertEqual(0, match, 'Keys must match')

    def test_signature_verification(self):
        "Test that signing and verification works"
        key = self.generate_key('Andrew', 'Able', 'alpha.com')
        if gnupg._py3k:
            data = 'Hello, André!'
        else:  # pragma: no cover
            data = unicode('Hello, André', self.gpg.encoding)
        data = data.encode(self.gpg.encoding)
        self.assertRaises(ValueError, self.gpg.sign, data, keyid=key.fingerprint, passphrase='bbr\x00own')
        self.assertRaises(ValueError, self.gpg.sign, data, keyid=key.fingerprint, passphrase='bbr\rown')
        self.assertRaises(ValueError, self.gpg.sign, data, keyid=key.fingerprint, passphrase='bbr\nown')
        sig = self.gpg.sign(data, keyid=key.fingerprint, passphrase='bbrown')
        self.assertFalse(sig, 'Bad passphrase should fail')
        sig = self.gpg.sign(data, keyid=key.fingerprint, passphrase='aable')
        self.assertEqual(0, sig.returncode, 'Non-zero return code')
        self.assertTrue(sig, 'Good passphrase should succeed')
        if sig.username:  # pragma: no cover
            # not set in recent versions of GnuPG e.g. 2.2.5
            self.assertTrue(sig.username.startswith('Andrew Able'))
        if sig.key_id:  # pragma: no cover
            self.assertTrue(key.fingerprint.endswith(sig.key_id))
        self.assertTrue(sig.hash_algo)
        logger.debug('verification start')
        verified = self.gpg.verify(sig.data)
        self.assertEqual(0, verified.returncode, 'Non-zero return code')
        logger.debug('verification end')
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug('key: %r', key.fingerprint)
            logger.debug('ver: %r', verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint, 'Fingerprints must match')
        self.assertEqual(verified.trust_level, verified.TRUST_ULTIMATE)
        self.assertEqual(verified.trust_text, 'TRUST_ULTIMATE')
        data_file = open(self.test_fn, 'rb')
        sig = self.gpg.sign_file(data_file, keyid=key.fingerprint, passphrase='aable')
        self.assertEqual(0, sig.returncode, 'Non-zero return code')
        data_file.close()
        self.assertTrue(sig, 'File signing should succeed')
        self.assertTrue(sig.hash_algo)
        try:
            stream = gnupg._make_binary_stream(sig.data, self.gpg.encoding)
            verified = self.gpg.verify_file(stream)
        except UnicodeDecodeError:  # pragma: no cover
            # sometimes happens in Python 2.6
            from io import BytesIO
            verified = self.gpg.verify_file(BytesIO(sig.data))
        self.assertEqual(0, verified.returncode, 'Non-zero return code')
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug('key: %r', key.fingerprint)
            logger.debug('ver: %r', verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint, 'Fingerprints must match')
        data_file = open(self.test_fn, 'rb')
        sig = self.gpg.sign_file(data_file, keyid=key.fingerprint, passphrase='aable', detach=True)
        self.assertEqual(0, sig.returncode, 'Non-zero return code')
        data_file.close()
        self.assertTrue(sig, 'File signing should succeed')
        self.assertTrue(sig.hash_algo)
        try:
            file = gnupg._make_binary_stream(sig.data, self.gpg.encoding)
            verified = self.gpg.verify_file(file, self.test_fn)
        except UnicodeDecodeError:  # pragma: no cover
            # sometimes happens in Python 2.6
            from io import BytesIO
            verified = self.gpg.verify_file(BytesIO(sig.data))
        self.assertEqual(0, verified.returncode, 'Non-zero return code')
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug('key: %r', key.fingerprint)
            logger.debug('ver: %r', verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint, 'Fingerprints must match')
        # Test in-memory verification
        data_file = open(self.test_fn, 'rb')
        data = data_file.read()
        data_file.close()
        fd, fn = tempfile.mkstemp(prefix='pygpg-test-')
        os.write(fd, sig.data)
        os.close(fd)
        try:
            verified = self.gpg.verify_data(fn, data)
        finally:
            os.remove(fn)
        self.assertEqual(0, verified.returncode, 'Non-zero return code')
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug('key: %r', key.fingerprint)
            logger.debug('ver: %r', verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint, 'Fingerprints must match')

    def test_signature_file(self):
        "Test that signing and verification works via the GPG output"
        key = self.generate_key('Andrew', 'Able', 'alpha.com')
        data_file = open(self.test_fn, 'rb')
        sig_file = self.test_fn + '.asc'
        sig = self.gpg.sign_file(data_file, keyid=key.fingerprint, passphrase='aable', detach=True, output=sig_file)
        self.assertEqual(0, sig.returncode, 'Non-zero return code')
        data_file.close()
        self.assertTrue(sig, 'File signing should succeed')
        self.assertTrue(sig.hash_algo)
        self.assertTrue(os.path.exists(sig_file))
        # Test in-memory verification
        data_file = open(self.test_fn, 'rb')
        data = data_file.read()
        data_file.close()
        try:
            verified = self.gpg.verify_data(sig_file, data)
            self.assertTrue(verified.username.startswith('Andrew Able'))
            self.assertTrue(key.fingerprint.endswith(verified.key_id))
        finally:
            os.remove(sig_file)
        self.assertEqual(0, verified.returncode, 'Non-zero return code')
        if key.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug('key: %r', key.fingerprint)
            logger.debug('ver: %r', verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint, 'Fingerprints must match')

    def test_subkey_signature_file(self):
        "Test that signing and verification works via the GPG output for subkeys"
        if self.gpg.version[0] < 2:  # pragma: no cover
            raise unittest.SkipTest('Feature unavailable in GnuPG 1.x')
        master_key = self.generate_key('Charlie', 'Clark', 'gamma.com', passphrase='123', with_subkey=False)
        self.assertEqual(0, master_key.returncode, 'Non-zero return code')

        subkey = self.gpg.add_subkey(master_key=master_key.fingerprint,
                                     master_passphrase='123',
                                     algorithm='dsa',
                                     usage='sign',
                                     expire=0)
        self.assertEqual(0, subkey.returncode, 'Non-zero return code')

        data_file = open(self.test_fn, 'rb')
        sig_file = self.test_fn + '.asc'
        sig = self.gpg.sign_file(data_file, keyid=subkey.fingerprint, passphrase='123', detach=True, output=sig_file)

        self.assertEqual(0, sig.returncode, 'Non-zero return code')
        data_file.close()
        self.assertTrue(sig, 'File signing should succeed')
        self.assertTrue(sig.hash_algo)
        self.assertTrue(os.path.exists(sig_file))
        # Test in-memory verification
        data_file = open(self.test_fn, 'rb')
        data = data_file.read()
        data_file.close()
        try:
            verified = self.gpg.verify_data(sig_file, data)
            self.assertTrue(verified.username.startswith('Charlie Clark'))
            self.assertTrue(subkey.fingerprint.endswith(verified.key_id))
        finally:
            os.remove(sig_file)
        self.assertEqual(0, verified.returncode, 'Non-zero return code')
        if subkey.fingerprint != verified.fingerprint:  # pragma: no cover
            logger.debug('key: %r', subkey.fingerprint)
            logger.debug('ver: %r', verified.fingerprint)
        self.assertEqual(subkey.fingerprint, verified.fingerprint, 'Fingerprints must match')

    def test_deletion(self):
        "Test that key deletion works"
        result = self.gpg.import_keys(KEYS_TO_IMPORT)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        public_keys = self.gpg.list_keys()
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 2), '2-element list expected')
        result = self.gpg.delete_keys(public_keys[0]['fingerprint'])
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        public_keys = self.gpg.list_keys()
        self.assertEqual(0, public_keys.returncode, 'Non-zero return code')
        self.assertTrue(is_list_with_len(public_keys, 1), '1-element list expected')

    def test_nogpg(self):
        "Test that absence of gpg is handled correctly"
        with self.assertRaises(OSError) as ar:
            gnupg.GPG(gnupghome=self.homedir, gpgbinary='frob')
        self.assertIn('frob', str(ar.exception))

    def test_invalid_home(self):
        "Test that any specified gnupghome directory actually is one"
        hd = tempfile.mkdtemp(prefix='keys-')
        shutil.rmtree(hd)  # make sure it isn't there anymore
        with self.assertRaises(ValueError) as ar:
            gnupg.GPG(gnupghome=hd)
        self.assertTrue('gnupghome should be a directory' in str(ar.exception))

    def test_make_args(self):
        "Test argument line construction"
        self.gpg.options = ['--foo', '--bar']
        args = self.gpg.make_args(['a', 'b'], False)
        self.assertTrue(len(args) > 4)
        self.assertEqual(args[-4:], ['--foo', '--bar', 'a', 'b'])

    def do_file_encryption_and_decryption(self, encfname, decfname):
        "Do the actual encryption/decryption test using given filenames"
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
            key = self.generate_key('Andrew', 'Able', 'alpha.com', passphrase='andy')
            self.assertEqual(0, key.returncode, 'Non-zero return code')
            andrew = key.fingerprint
            key = self.generate_key('Barbara', 'Brown', 'beta.com')
            self.assertEqual(0, key.returncode, 'Non-zero return code')
            barbara = key.fingerprint
            data = 'Hello, world!'
            stream = gnupg._make_binary_stream(data, self.gpg.encoding)
            edata = self.gpg.encrypt_file(stream, [andrew, barbara], armor=False, output=encfname)
            self.assertEqual(0, edata.returncode, 'Non-zero return code')
            efile = open(encfname, 'rb')
            ddata = self.gpg.decrypt_file(efile, passphrase='bbrown', output=decfname)
            self.assertEqual(0, ddata.returncode, 'Non-zero return code')
            efile.seek(0, os.SEEK_SET)
            edata = efile.read()
            efile.close()
            self.assertTrue(os.path.exists(decfname))
            dfile = open(decfname, 'rb')
            ddata = dfile.read()
            dfile.close()
            data = data.encode(self.gpg.encoding)
            if ddata != data:  # pragma: no cover
                logger.debug('was: %r', data)
                logger.debug('new: %r', ddata)
            self.assertEqual(data, ddata, 'Round-trip must work')

            # Try opening the encrypted file in text mode (Issue #39)
            # this doesn't fail in 2.x
            if gnupg._py3k:
                efile = open(encfname, 'r')
                ddata = self.gpg.decrypt_file(efile, passphrase='bbrown', output=decfname)
                self.assertEqual(2, ddata.returncode, 'Unexpected return code')
                self.assertFalse(ddata)
                self.assertEqual(ddata.status, 'no data was provided')
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
        encfno, encfname = tempfile.mkstemp(prefix='pygpg-test-')
        decfno, decfname = tempfile.mkstemp(prefix='pygpg-test-')
        # On Windows, if the handles aren't closed, the files can't be deleted
        os.close(encfno)
        os.close(decfno)
        self.do_file_encryption_and_decryption(encfname, decfname)

    @skipIf(os.name == 'nt', 'Test not suitable for Windows')
    def test_invalid_outputs(self):
        "Test encrypting to invalid output files"
        encfno, encfname = tempfile.mkstemp(prefix='pygpg-test-')
        os.close(encfno)
        os.chmod(encfname, 0o400)
        cases = (
            ('/dev/null/foo', 'encrypt: not a directory'),
            (encfname, 'encrypt: permission denied'),
        )
        key = self.generate_key('Barbara', 'Brown', 'beta.com')
        barbara = key.fingerprint
        data = 'Hello, world!'
        for badout, message in cases:
            stream = gnupg._make_binary_stream(data, self.gpg.encoding)
            edata = self.gpg.encrypt_file(stream, barbara, armor=False, output=badout)
            self.assertEqual(2, edata.returncode, 'Unexpecteds return code')
            # on GnuPG 1.4, you sometimes don't get any FAILURE messages, in
            # which case status will not be set
            if edata.status:
                self.assertEqual(edata.status, message)

        # now try with custom error map, if available
        if os.path.exists('messages.json'):
            with open('messages.json') as f:
                mdata = json.load(f)
            messages = {}
            for k, v in mdata.items():
                messages[int(k, 16)] = v

            self.gpg.error_map = messages

            encfno, encfname = tempfile.mkstemp(prefix='pygpg-test-')
            os.close(encfno)
            os.chmod(encfname, 0o400)

            try:
                cases = (
                    ('/dev/null/foo', 'encrypt: Not a directory'),
                    (encfname, 'encrypt: Permission denied'),
                )

                for badout, message in cases:
                    stream = gnupg._make_binary_stream(data, self.gpg.encoding)
                    edata = self.gpg.encrypt_file(stream, barbara, armor=False, output=badout)
                    self.assertEqual(2, edata.returncode, 'Unexpected return code')
                    # on GnuPG 1.4, you sometimes don't get any FAILURE messages, in
                    # which case status will not be set
                    if edata.status:
                        self.assertEqual(edata.status, message)
            finally:
                os.chmod(encfname, 0o700)
                os.remove(encfname)

    def test_filenames_with_spaces(self):  # See Issue #16
        "Test that filenames with spaces are correctly handled"
        d = tempfile.mkdtemp()
        try:
            encfname = os.path.join(d, 'encrypted file')
            decfname = os.path.join(d, 'decrypted file')
            self.do_file_encryption_and_decryption(encfname, decfname)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # This test does nothing on CI because it often leads to failures due to
    # external servers being down
    def test_search_keys(self):  # pragma: no cover
        "Test that searching for keys works"

        if 'NO_EXTERNAL_TESTS' not in os.environ:
            r = self.gpg.search_keys('<vinay_sajip@hotmail.com>')
            self.assertEqual(0, r.returncode, 'Non-zero return code')
            self.assertTrue(r)
            self.assertTrue('Vinay Sajip <vinay_sajip@hotmail.com>' in r[0]['uids'])
            r = self.gpg.search_keys('92905378')
            self.assertEqual(0, r.returncode, 'Non-zero return code')
            self.assertTrue(r)
            self.assertTrue('Vinay Sajip <vinay_sajip@hotmail.com>' in r[0]['uids'])

    def test_quote_with_shell(self):
        "Test shell quoting with a real shell"
        if os.name != 'posix':
            return

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
            shutil.rmtree(workdir, ignore_errors=True)

    def disabled_test_signing_with_uid(self):  # pragma: no cover
        "Test that signing with uids works. On hold for now."
        self.generate_key('Andrew', 'Able', 'alpha.com')
        uid = self.gpg.list_keys(True)[-1]['uids'][0]
        try:
            signfile = open(self.test_fn, 'rb')
            signed = self.gpg.sign_file(signfile, keyid=uid, passphrase='aable', detach=True)
        finally:
            signfile.close()
        self.assertEqual(0, signed.returncode, 'Non-zero return code')
        self.assertTrue(signed.data)

    def test_doctest_import_keys(self):
        """
        Because GnuPG 2.1 requires passphrases for exporting and deleting
        secret keys, and because console-mode passphrase entry requires
        configuration changes, doctests can't always be used. This test
        replicates the original doctest for import_keys as a regular test.

        >>> import shutil
        >>> shutil.rmtree("keys", ignore_errors=True)
        >>> GPGBINARY = os.environ.get('GPGBINARY', 'gpg')
        >>> gpg = GPG(gpgbinary=GPGBINARY, gnupghome="keys")
        >>> input = gpg.gen_key_input(name_email='user1@test', passphrase='pp1')
        >>> result = gpg.gen_key(input)
        >>> fp1 = result.fingerprint
        >>> result = gpg.gen_key(input)
        >>> fp2 = result.fingerprint
        >>> pubkey1 = gpg.export_keys(fp1)
        >>> seckey1 = gpg.export_keys(fp1, secret=True, passphrase='pp1')
        >>> seckeys = gpg.list_keys(secret=True)
        >>> pubkeys = gpg.list_keys()
        >>> assert fp1 in seckeys.fingerprints
        >>> assert fp1 in pubkeys.fingerprints
        >>> str(gpg.delete_keys(fp1))
        'Must delete secret key first'
        >>> str(gpg.delete_keys(fp1, secret=True, passphrase='pp1'))
        'ok'
        >>> str(gpg.delete_keys(fp1))
        'ok'
        >>> str(gpg.delete_keys("nosuchkey"))
        'No such key'
        >>> seckeys = gpg.list_keys(secret=True)
        >>> pubkeys = gpg.list_keys()
        >>> assert not fp1 in seckeys.fingerprints
        >>> assert not fp1 in pubkeys.fingerprints
        >>> result = gpg.import_keys('foo')
        >>> assert not result
        >>> result = gpg.import_keys(pubkey1)
        >>> pubkeys = gpg.list_keys()
        >>> seckeys = gpg.list_keys(secret=True)
        >>> assert not fp1 in seckeys.fingerprints
        >>> assert fp1 in pubkeys.fingerprints
        >>> result = gpg.import_keys(seckey1)
        >>> assert result
        >>> seckeys = gpg.list_keys(secret=True)
        >>> pubkeys = gpg.list_keys()
        >>> assert fp1 in seckeys.fingerprints
        >>> assert fp1 in pubkeys.fingerprints
        >>> assert fp2 in pubkeys.fingerprints
        """
        gpg = self.gpg
        inp = gpg.gen_key_input(name_email='user1@test', passphrase='pp1')
        result = gpg.gen_key(inp)
        fp1 = result.fingerprint
        inp = gpg.gen_key_input(name_email='user2@test', passphrase='pp2')
        result = gpg.gen_key(inp)
        self.assertEqual(0, result.returncode, 'Non-zero return code')
        fp2 = result.fingerprint
        pubkey1 = gpg.export_keys(fp1)
        self.assertTrue(pubkey1)
        if gpg.version >= (2, 1):
            passphrase = 'pp1'
        else:  # pragma: no cover
            passphrase = None
        seckey1 = gpg.export_keys(fp1, secret=True, passphrase=passphrase)
        self.assertTrue(seckey1)
        seckeys = gpg.list_keys(secret=True)
        self.assertEqual(0, seckeys.returncode, 'Non-zero return code')
        pubkeys = gpg.list_keys()
        self.assertEqual(0, pubkeys.returncode, 'Non-zero return code')
        for fp in (fp1, fp2):
            for keys in (seckeys, pubkeys):
                self.assertIn(fp, keys.fingerprints)
        result = gpg.delete_keys(fp1)
        self.assertEqual(2, result.returncode, 'Unexpected return code')
        self.assertEqual(str(result), 'Must delete secret key first')
        if gpg.version < (2, 1):  # pragma: no cover
            # Doesn't work on 2.1, and can't use SkipTest due to having
            # to support older Pythons
            result = gpg.delete_keys(fp1, secret=True, passphrase=passphrase)
            self.assertEqual(0, result.returncode, 'Non-zero return code')
            self.assertEqual(str(result), 'ok')
            result = gpg.delete_keys(fp1)
            self.assertEqual(0, result.returncode, 'Non-zero return code')
            self.assertEqual(str(result), 'ok')
            result = gpg.delete_keys('nosuchkey')
            self.assertEqual(2, result.returncode, 'Unexpected return code')
            self.assertEqual(str(result), 'No such key')
            seckeys = gpg.list_keys(secret=True)
            self.assertEqual(0, seckeys.returncode, 'Non-zero return code')
            pubkeys = gpg.list_keys()
            self.assertEqual(0, pubkeys.returncode, 'Non-zero return code')
            self.assertFalse(fp1 in seckeys.fingerprints)
            self.assertFalse(fp1 in pubkeys.fingerprints)
            result = gpg.import_keys('foo')
            self.assertFalse(result)

    def test_recv_keys_no_server(self):
        result = self.gpg.recv_keys('foo.bar.baz', '92905378')
        self.assertEqual(2, result.returncode, 'Unexpected return code')
        self.assertEqual(result.summary(), '0 imported')

    def test_invalid_fileobject(self):
        # accidentally on purpose pass in a filename rather than the file itself
        bad = b'foobar.txt'
        with self.assertRaises((TypeError, ValueError)) as ec:
            self.gpg.decrypt_file(bad, passphrase='', output='/tmp/decrypted.txt')
        if gnupg._py3k:
            expected = 'Not a valid file or path: %s' % bad
        else:
            expected = 'No such file: %s' % bad
        self.assertEqual(str(ec.exception), expected)

    def remove_all_existing_keys(self):
        for root, dirs, files in os.walk(self.homedir):
            for d in dirs:
                p = os.path.join(root, d)
                shutil.rmtree(p)
            for f in files:
                if f.endswith('.conf'):
                    continue
                p = os.path.join(root, f)
                os.remove(p)

    def test_no_such_key(self):
        key = self.generate_key('Barbara', 'Brown', 'beta.com')
        barbara = key.fingerprint
        gpg = self.gpg
        if gnupg._py3k:
            data = 'Hello, André!'
        else:  # pragma: no cover
            data = unicode('Hello, André', gpg.encoding)
        data = data.encode(gpg.encoding)
        encrypted = gpg.encrypt(data, barbara)
        self.remove_all_existing_keys()
        decrypted = gpg.decrypt(str(encrypted), passphrase='bbrown')
        self.assertFalse(decrypted.ok)
        expected = {'decryption failed', 'no secret key', 'no data was provided'}
        self.assertIn(decrypted.status, expected)

    def test_get_recipients(self):
        gpg = self.gpg
        inp = gpg.gen_key_input(name_email='user1@test', passphrase='pp1')
        key1 = gpg.gen_key(inp)
        inp = gpg.gen_key_input(name_email='user2@test', passphrase='pp2')
        key2 = gpg.gen_key(inp)
        data = 'super secret'.encode(gpg.encoding)
        edata = gpg.encrypt(data, (key1.fingerprint, key2.fingerprint))
        logger.debug('Getting recipients')
        ids = gpg.get_recipients(edata.data.decode(gpg.encoding))
        self.assertGreater(len(ids), 0)
        idlen = len(ids[0])
        ids = set(ids)
        expected = set((key1.fingerprint[-idlen:], key2.fingerprint[-idlen:]))
        self.assertEqual(expected, ids)

    def test_passing_paths(self):
        key1 = self.generate_key('Andrew', 'Able', 'alpha.com', passphrase='andy')
        self.assertEqual(0, key1.returncode, 'Non-zero return code')
        andrew = key1.fingerprint
        key2 = self.generate_key('Barbara', 'Brown', 'beta.com')
        self.assertEqual(0, key2.returncode, 'Non-zero return code')
        barbara = key2.fingerprint
        data = b'Hello, world!'
        fd, fn = tempfile.mkstemp(prefix='pygpg-test-')
        os.write(fd, data)
        os.close(fd)
        gpg = self.gpg
        try:
            # Check encryption
            edata = gpg.encrypt_file(fn, [andrew, barbara], armor=False)
            self.assertEqual(0, edata.returncode, 'Non-zero return code')
            self.assertEqual(edata.status, 'encryption ok')
            with open(fn, 'wb') as f:
                f.write(edata.data)
            # Check getting recipients
            ids = gpg.get_recipients_file(fn)
            idlen = len(ids[0])
            keys = gpg.list_keys()
            expected = set(d['subkeys'][0][0][-idlen:] for d in keys)
            self.assertEqual(set(ids), expected)
            # Check decryption
            ddata = gpg.decrypt_file(fn, passphrase='andy')
            self.assertEqual(0, ddata.returncode, 'Non-zero return code')
            self.assertEqual(ddata.status, 'decryption ok')
            self.assertEqual(ddata.data, data)
            # Check signing
            with open(fn, 'wb') as f:
                f.write(data)
            sig = gpg.sign_file(fn, keyid=andrew, passphrase='andy', binary=True)
            self.assertEqual(0, sig.returncode, 'Non-zero return code')
            self.assertEqual(sig.status, 'signature created')
            # Check verification
            with open(fn, 'wb') as f:
                f.write(sig.data)
            verified = gpg.verify_file(fn)
            self.assertEqual(0, verified.returncode, 'Non-zero return code')
            self.assertEqual(verified.status, 'signature valid')
            self.assertTrue(verified.valid)
            # Check importing keys
            with open(fn, 'wb') as f:
                f.write(KEYS_TO_IMPORT.encode('ascii'))
            result = gpg.import_keys_file(fn)
            self.assertEqual(0, result.returncode, 'Non-zero return code')
            self.assertEqual(result.imported, 2)
        finally:
            os.remove(fn)

    def test_multiple_signatures(self):
        gpg = self.gpg
        key1 = self.generate_key('Andrew', 'Able', 'alpha.com')
        key2 = self.generate_key('Barbara', 'Brown', 'beta.com')
        data = b'signed data'
        sig1 = gpg.sign(data, keyid=key1.fingerprint, passphrase='aable', detach=True)
        sig2 = gpg.sign(data, keyid=key2.fingerprint, passphrase='bbrown', detach=True)
        # Combine the signatures, then verify
        fd, fn = tempfile.mkstemp(prefix='pygpg-test-')
        os.write(fd, sig1.data)
        os.write(fd, sig2.data)
        os.close(fd)
        try:
            verified = self.gpg.verify_data(fn, data)
            sig_info = verified.sig_info
            self.assertEqual(len(sig_info), 2)
            actual = set(d['fingerprint'] for d in sig_info.values())
            expected = set((key1.fingerprint, key2.fingerprint))
            self.assertEqual(actual, expected)
        finally:
            os.remove(fn)

    def test_multiple_signatures_one_invalid(self):
        gpg = self.gpg
        key1 = self.generate_key('Andrew', 'Able', 'alpha.com')
        key2 = self.generate_key('Barbara', 'Brown', 'beta.com')
        data = b'signed data'
        other_data = b'other signed data'
        sig1 = gpg.sign(data, keyid=key1.fingerprint, passphrase='aable', detach=True)
        sig2 = gpg.sign(other_data, keyid=key2.fingerprint, passphrase='bbrown', detach=True)
        # Combine the signatures, then verify
        fd, fn = tempfile.mkstemp(prefix='pygpg-test-')
        os.write(fd, sig1.data)
        os.write(fd, sig2.data)
        os.close(fd)
        try:
            verified = self.gpg.verify_data(fn, data)
            sig_info = verified.sig_info
            self.assertEqual(len(sig_info), 1)
            actual = set(d['fingerprint'] for d in sig_info.values())
            expected = set([key1.fingerprint])
            self.assertEqual(actual, expected)
            problems = verified.problems
            self.assertEqual(len(problems), 1)
            d = problems[0]
            self.assertEqual(d['status'], 'signature bad')
            self.assertTrue(key2.fingerprint.endswith(d['keyid']))
        finally:
            os.remove(fn)


TEST_GROUPS = {
    'sign':
    set(['test_signature_verification', 'test_signature_file', 'test_subkey_signature_file']),
    'crypt':
    set([
        'test_encryption_and_decryption', 'test_file_encryption_and_decryption', 'test_filenames_with_spaces',
        'test_invalid_outputs', 'test_no_such_key'
    ]),
    'key':
    set([
        'test_deletion', 'test_import_and_export', 'test_list_keys_after_generation', 'test_list_signatures',
        'test_key_generation_with_invalid_key_type', 'test_key_generation_with_escapes', 'test_key_generation_input',
        'test_key_generation_with_colons', 'test_search_keys', 'test_scan_keys', 'test_scan_keys_mem',
        'test_key_trust', 'test_add_subkey', 'test_add_subkey_with_invalid_key_type', 'test_deletion_subkey',
        'test_list_subkey_after_generation'
    ]),
    'import':
    set(['test_import_only', 'test_doctest_import_keys']),
    'basic':
    set(['test_environment', 'test_list_keys_initial', 'test_nogpg', 'test_make_args', 'test_quote_with_shell']),
    'test':
    set(['test_multiple_signatures_one_invalid']),
}


def suite(args=None):
    if args is None:  # pragma: no cover
        args = sys.argv[1:]
    if not args:
        result = unittest.TestLoader().loadTestsFromTestCase(GPGTestCase)
    else:  # pragma: no cover
        tests = set()
        for arg in args:
            if arg in TEST_GROUPS:
                tests.update(TEST_GROUPS[arg])
            else:
                print('Ignoring unknown test group %r' % arg)
        result = unittest.TestSuite(list(map(GPGTestCase, tests)))
    return result


def init_logging():
    logging.basicConfig(level=logging.DEBUG,
                        filename='test_gnupg.log',
                        filemode='w',
                        format='%(asctime)s %(levelname)-5s %(name)-10s '
                        '%(threadName)-10s %(lineno)4d %(message)s')


def main():
    init_logging()
    logger.debug('Python version: %s', sys.version.replace('\n', ' '))
    adhf = argparse.ArgumentDefaultsHelpFormatter
    ap = argparse.ArgumentParser(formatter_class=adhf, prog='test_gnupg')
    aa = ap.add_argument
    aa('-v', '--verbose', default=False, action='store_true', help='Increase verbosity')
    options, args = ap.parse_known_args()
    tests = suite(args)
    verbosity = 2 if options.verbose else 1
    results = unittest.TextTestRunner(verbosity=verbosity).run(tests)
    failed = not results.wasSuccessful()
    if failed and 'TOXENV' in os.environ and os.name != 'posix':  # pragma: no cover
        os.system('type test_gnupg.log')
    return failed


if __name__ == '__main__':
    sys.exit(main())
