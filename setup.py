from distutils.core import setup

from gnupg import __version__ as version

setup(name = "python-gnupg",
    description="A wrapper for the Gnu Privacy Guard (GPG or GnuPG)",
    long_description = "This module allows easy access to GnuPG's key \
management, encryption and signature functionality from Python programs. \
It is intended for use with Python 2.4 or greater.",
    license="""Copyright (C) 2008-2016 by Vinay Sajip. All Rights Reserved. See LICENSE.txt for license.""",
    version=version,
    author="Vinay Sajip",
    author_email="vinay_sajip@red-dove.com",
    maintainer="Vinay Sajip",
    maintainer_email="vinay_sajip@red-dove.com",
    url="http://packages.python.org/python-gnupg/index.html",
    py_modules=["gnupg"],
    platforms="No particular restrictions",
    download_url="https://pypi.python.org/packages/source/p/python-gnupg/python-gnupg-%s.tar.gz" % version,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        "Intended Audience :: Developers",
        'License :: OSI Approved :: BSD License',
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.4",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
