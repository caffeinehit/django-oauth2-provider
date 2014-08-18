django-oauth2-provider
======================

.. image:: https://travis-ci.org/caffeinehit/django-oauth2-provider.png?branch=master

*django-oauth2-provider* is a Django application that provides
customizable OAuth2\-authentication for your Django projects.

`Documentation <http://readthedocs.org/docs/django-oauth2-provider/en/latest/>`_

`Help <https://groups.google.com/d/forum/django-oauth2-provider>`_


Open ID Connect
---------------
The `openid` and `profile` scopes are included in the default scopes. In order to properly conform to the Open ID Connect
spec, set the value of the setting `OAUTH_OIDC_ISSUER` to the issuer URL for your Open ID Connect provider. The ID token
expiration, which defaults to 30 seconds, can be overriden by setting `OAUTH_ID_TOKEN_EXPIRATION`.

License
=======

*django-oauth2-provider* is released under the MIT License. Please see the LICENSE file for details.
