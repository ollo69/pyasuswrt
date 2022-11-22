#!/usr/bin/env python
"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from os.path import dirname, join
import re

from setuptools import find_packages, setup

LIB = "pyasuswrt"
install_requires = ["aiohttp>=3.7.4"]
github_url = "https://github.com/ollo69/pyasuswrt"

with open(join(dirname(__file__), LIB, "__init__.py"), "r") as fp:
    for line in fp:
        m = re.search(r'^\s*__version__\s*=\s*([\'"])([^\'"]+)\1\s*$', line)
        if m:
            version = m.group(2)
            break
    else:
        raise RuntimeError("Unable to find own __version__ string")

with open("README.md", "r") as f:
    readme = f.read()

setup(
    name="pyasuswrt",
    version=version,
    description="Api wrapper for Asuswrt https://www.asus.com/ASUSWRT/ using protocol HTTP",
    long_description=readme,
    long_description_content_type="text/markdown",
    keywords=["asuswrt", "asuswrt wrapper"],
    url=github_url,
    download_url=f"{github_url}/archive/{version}.tar.gz",
    license="MIT",
    author="ollo69",
    author_email="ollo69@users.noreply.github.com",
    packages=find_packages(exclude=["contrib", "docs", "tests"]),
    python_requires=">=3.7",
    install_requires=install_requires,
    extras_require={},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
    ],
    test_suite="tests",
)
