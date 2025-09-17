#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='django-oauth2',
    long_description=open('README.rst').read(),
    packages=find_packages(exclude=('tests*',)),
    include_package_data=True,
    zip_safe=False,
)
