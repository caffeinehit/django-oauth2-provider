
`provider`
==========

`provider.constants`
--------------------
.. automodule:: provider.constants
    :members:
    :no-undoc-members:

.. currentmodule:: provider.constants

.. attribute:: RESPONSE_TYPE_CHOICES

    :settings: `OAUTH_RESPONSE_TYPE_CHOICES`

    The response types as outlined by :rfc:`3.1.1`

.. attribute:: SCOPES

    :settings: `OAUTH_SCOPES`

    A choice of scopes. A detailed implementation is left to the developer.
    The current default implementation in :attr:`provider.oauth2.scope` makes
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

    To have the provider only create and retrieve one access token per
    user/client/scope combination, set to `True`.

`provider.forms`
----------------
.. automodule:: provider.forms
    :members:
    :no-undoc-members:

`provider.scope`
-----------------------
.. automodule:: provider.scope
    :members:
    :no-undoc-members:

`provider.templatetags.scope`
-----------------------------
.. automodule:: provider.templatetags.scope
    :members:
    :no-undoc-members:

`provider.utils`
----------------
.. automodule:: provider.utils
    :members:
    :no-undoc-members:

`provider.views`
----------------
.. automodule:: provider.views
    :members:
    :no-undoc-members:


`provider.oauth2`
=================

`provider.oauth2.forms`
-----------------------
.. automodule:: provider.oauth2.forms
    :members:
    :no-undoc-members:

`provider.oauth2.models`
------------------------
.. automodule:: provider.oauth2.models
    :members:
    :no-undoc-members:

`provider.oauth2.urls`
----------------------
.. automodule:: provider.oauth2.urls
    :members:
    :no-undoc-members:

`provider.oauth2.views`
-----------------------
.. automodule:: provider.oauth2.views
    :members:
    :no-undoc-members:
