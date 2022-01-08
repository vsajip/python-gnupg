from setuptools import setup

from gnupg import __version__ as version

setup(
    name="python-gnupg",
    description="A wrapper for the Gnu Privacy Guard (GPG or GnuPG)",
    long_description="""This module allows easy access to GnuPG's key \
management, encryption and signature functionality from Python programs. \
It is intended for use with Python 2.4 or greater.

Releases are normally signed using a GnuPG key with the user id \
vinay_sajip@yahoo.co.uk and the following fingerprint:

CA74 9061 914E AC13 8E66  EADB 9147 B477 339A 9B86

As PyPI no longer shows signatures, you should be able to download release archives \
and signatures from

https://github.com/vsajip/python-gnupg/releases

or older releases from

https://bitbucket.org/vinay.sajip/python-gnupg/downloads/

The archives should be the same as those uploaded to PyPI.
""",
    license="""Copyright (C) 2008-2021 by Vinay Sajip. All Rights Reserved. See LICENSE.txt for license.""",
    version=version,
    author="Vinay Sajip",
    author_email="vinay_sajip@yahoo.co.uk",
    maintainer="Vinay Sajip",
    maintainer_email="vinay_sajip@yahoo.co.uk",
    url="https://docs.red-dove.com/python-gnupg/",
    project_urls={
        "Documentation": "https://docs.red-dove.com/python-gnupg/",
        "Source": "https://github.com/vsajip/python-gnupg",
        "Changelog": "https://github.com/vsajip/python-gnupg/#change-log",
    },
    py_modules=["gnupg"],
    platforms="No particular restrictions",
    download_url="https://pypi.io/packages/source/p/python-gnupg/python-gnupg-%s.tar.gz" % version,
    classifiers=[
        'Development Status :: 5 - Production/Stable', "Intended Audience :: Developers",
        'License :: OSI Approved :: BSD License', "Programming Language :: Python",
        "Programming Language :: Python :: 2", "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.7", "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7", "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ])
