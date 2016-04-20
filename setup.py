#!/usr/bin/env python

import os
import re
import sys

# prefer setuptools over distutils
from setuptools import setup, find_packages
# to use a consistent encoding
from codecs import open

root = os.path.abspath(os.path.dirname(__file__))
def here(filename):
    return os.path.join(root, filename)

version = None
with open(here('microsecrets.py'), 'r', encoding='utf-8') as f:
    version = re.search(r'^VERSION\s*=\s*[\'"]([^\'"]*)[\'"]',
                        f.read(), re.MULTILINE).group(1)
if not version:
    raise RuntimeError('Cannot find version information')

# get the long description from the README file
with open(here('README.rst'), 'r', encoding='utf-8') as f:
    readme = f.read()

setup(
    name='microsecrets',
    version=version,
    description='Simple secrets management powered by Amazon S3 + KMS',
    long_description=readme,
    url='https://github.com/uscis/microsecrets',

    packages=find_packages(exclude=['docs', 'tests*']),
    # currently no packages; just a single module
    py_modules=['microsecrets'],

    author='Andy Brody',
    author_email='git@abrody.com',

    license='Public Domain',

    # TODO: switch to console_scripts instead of scripts
    scripts=[
        'bin/microsecrets-upload',
        'bin/microsecrets-with-env',
        'bin/microsecrets-download',
    ],

    # TODO: generate from requirements.txt
    install_requires=[
        'boto3 >= 1.3.0, < 2.0',
    ],

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Security',

        # Pick your license as you wish (should match "license" above)
        'License :: Public Domain',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
)

