#!/usr/bin/env python

from setuptools import setup, find_packages
import provider

setup(
    name='django-oauth2-provider',
    version=provider.__version__,
    description='Provide OAuth2 access to your app',
    long_description=open('README.rst').read(),
    author='Alen Mujezinovic',
    author_email='alen@caffeinehit.com',
    url = 'https://github.com/caffeinehit/django-oauth2-provider',
    packages= find_packages(exclude=('tests*',)),
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
    ],
    install_requires=[
        "shortuuid>=0.3"
    ],
    include_package_data=True,
    zip_safe=False,
)
