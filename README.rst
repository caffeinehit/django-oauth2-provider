django-oauth2-provider
======================

.. image:: https://travis-ci.org/edx/django-oauth2-provider.svg?branch=edx
    :target: https://travis-ci.org/edx/django-oauth2-provider

.. image:: http://codecov.io/github/edx/django-oauth2-provider/coverage.svg?branch=edx
    :target: http://codecov.io/github/edx/django-oauth2-provider?branch=edx

This is an edX-customized fork of *django-oauth2-provider*, a Django application that provides
customizable OAuth2\-authentication for your Django projects.

`Documentation <http://readthedocs.org/docs/django-oauth2-provider/en/latest/>`_

`Help <https://groups.google.com/d/forum/django-oauth2-provider>`_

Release Notes
=============

1.0.2
-----

This release contains a backward incompatible change:

* Foreign key reverse names have been specified, so this library can be 
  installed alongside `django-oauth-toolkit`.  Code that traverses from 
  the User model to `django-oauth2-provider` models will need to update the 
  related name used.  

      >>> user.access_token
      >>> user.grant
      >>> user.refresh_token

  becomes:

      >>> user.dop_access_token
      >>> user.dop_grant
      >>> user.dop_refresh_token

License
=======

*django-oauth2-provider* is released under the MIT License. Please see the LICENSE file for details.
