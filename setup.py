#!/usr/bin/env python

# $Id$

from distutils.core import setup

# setup vars
dist_name = 'dsniff'
ver = '3.0a'
desc = 'dsniff is a simple Python application framework for network monitoring.'
auth = 'Dug Song'
email = 'dugsong@monkey.org'
license = 'GNU General Public License 2.0'
website = 'http://code.google.com/p/dsniff'
platform = 'linux'
dist_modules = ['dsniff','dsniff.core','dsniff.lib','dsniff.mail']
scripts = []
# setup command
setup(name = dist_name,
        version = ver,
        description = desc,
        maintainer = auth,
        maintainer_email = email,
        license = license,
        url = website,
        platforms = platform,
        packages = dist_modules,
        scripts = scripts,
    )

