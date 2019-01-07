#!/usr/bin/env python

from setuptools import setup, find_packages
import provider

setup(
    name='django-oauth2',
    version=provider.__version__,
    description='Provide OAuth2 access to your app (fork of django-oauth2-provider)',
    long_description=open('README.rst').read(),
    author='Shaun Kruger',
    author_email='shaun.kruger@gmail.com',
    url = 'https://github.com/stormsherpa/django-oauth2-provider',
    packages= find_packages(exclude=('tests*',)),
    license='The MIT License: http://www.opensource.org/licenses/mit-license.php',
    platforms='all',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
    ],
    install_requires=[
        "shortuuid>=0.4",
        "six>=0.11.0",
        "sqlparse>=0.2.4",
    ],
    include_package_data=True,
    zip_safe=False,
)
