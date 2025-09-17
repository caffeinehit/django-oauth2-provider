v 4.1
-----
* Add aws_identity grant_type
* Update for Django 3.1-4.2

v 4.0
-----
* Update for Django 3.0-4.1

v 2.4
-----
* Add HTTP Authorization Bearer token support to Oauth2UserMiddleware

v 2.3
-----
* Increase oauth2 scope name field size

v 2.2
-----
* Improve Oauth2UserMiddleware
* Prevent SessionMiddleware from creating new sessions when using oauth tokens.
* Add OAuthRequiredMixin to allow scope enforcement

v 2.1
-----
* Fixed documentation links.  Removed 2.0 package.

v 2.0
-----
* Update for current Django 1.11, 2.0, and 2.1.

v 1.2
-----
Updated to make scopes configurable in the database and update for Django 1.7

v 1.0
-----
Forked from original project at caffeinehit/django-oauth2-provider

v 0.2
-----
* *Breaking change* Moved ``provider.oauth2.scope`` to ``provider.scope``
* *Breaking change* Replaced the write scope with a new write scope that includes reading
* Default scope for new ``provider.oauth2.models.AccessToken`` is now ``provider.constants.SCOPES[0][0]``
* Access token response returns a space seperated list of scopes instead of an integer value
