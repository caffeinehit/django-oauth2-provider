
`djoauth2`
==========

`djoauth2.constants`
--------------------
.. automodule:: djoauth2.constants
    :members:
    :no-undoc-members:

.. currentmodule:: djoauth2.constants

.. attribute:: RESPONSE_TYPE_CHOICES

    :settings: `OAUTH_RESPONSE_TYPE_CHOICES`

    The response types as outlined by :rfc:`3.1.1`

.. attribute:: SCOPES

    :settings: `OAUTH_SCOPES`

    A choice of scopes. A detailed implementation is left to the developer.
    The current default implementation in :attr:`djoauth2.oauth2.scope` makes
    use of bit shifting operations to combine read and write permissions.

.. attribute:: EXPIRE_DELTA

    :settings: `OAUTH_EXPIRE_DELTA`
    :default: `datetime.timedelta(days=365)`

    The time to expiry for access tokens as outlined in :rfc:`4.2.2` and
    :rfc:`5.1`.
    
.. attribute:: EXPIRE_CODE_DELTA

    :settings: `OAUTH_EXPIRE_CODE_DELTA`
    :default: `datetime.timedelta(seconds=10*60)`

    The time to expiry for an authorization code grant as outlined in :rfc:`4.1.2`.

.. attribute:: DELETE_EXPIRED

    :settings: `OAUTH_DELETE_EXPIRED`
    :default: `False`

    To remove expired tokens immediately instead of letting them persist, set
    to `True`.

.. attribute:: ENFORCE_SECURE

    :settings: `OAUTH_ENFORCE_SECURE`
    :default: `False`

    To enforce secure communication on application level, set to `True`.

.. attribute:: SESSION_KEY

    :settings: `OAUTH_SESSION_KEY`
    :default: `"oauth"`

    Session key prefix to store temporary data while the user is completing
    the authentication / authorization process.

.. attribute:: SINGLE_ACCESS_TOKEN

    :settings: `OAUTH_SINGLE_ACCESS_TOKEN`
    :default: `False`

    To have the djoauth2 only create and retrieve one access token per
    user/client/scope combination, set to `True`.

`djoauth2.forms`
----------------
.. automodule:: djoauth2.forms
    :members:
    :no-undoc-members:

`djoauth2.scope`
-----------------------
.. automodule:: djoauth2.scope
    :members:
    :no-undoc-members:

`djoauth2.templatetags.scope`
-----------------------------
.. automodule:: djoauth2.templatetags.scope
    :members:
    :no-undoc-members:

`djoauth2.utils`
----------------
.. automodule:: djoauth2.utils
    :members:
    :no-undoc-members:

`djoauth2.views`
----------------
.. automodule:: djoauth2.views
    :members:
    :no-undoc-members:


`djoauth2.oauth2`
=================

`djoauth2.oauth2.forms`
-----------------------
.. automodule:: djoauth2.oauth2.forms
    :members:
    :no-undoc-members:

`djoauth2.oauth2.models`
------------------------
.. automodule:: djoauth2.oauth2.models
    :members:
    :no-undoc-members:

`djoauth2.oauth2.urls`
----------------------
.. automodule:: djoauth2.oauth2.urls
    :members:
    :no-undoc-members:

`djoauth2.oauth2.views`
-----------------------
.. automodule:: djoauth2.oauth2.views
    :members:
    :no-undoc-members:
