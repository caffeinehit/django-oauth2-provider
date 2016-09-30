#!/usr/bin/env python

from setuptools import setup, find_packages

import provider

setup(
    name='edx-django-oauth2-provider',
    version=provider.__version__,
    description='edX fork of django-oauth2-provider',
    long_description=open('README.rst').read(),
    author='edX',
    author_email='oscm@edx.org',
    url='https://github.com/edx/django-oauth2-provider',
    packages=find_packages(exclude=('tests*',)),
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
    ],
    install_requires=[
        'shortuuid>=0.4.3,<1.0.0'
    ],
    include_package_data=True,
    zip_safe=False,
)
