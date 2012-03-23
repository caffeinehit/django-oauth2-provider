
v 0.2
-----
* *Breaking change* Moved ``provider.oauth2.scope`` to ``provider.scope``
* *Breaking change* Replaced the write scope with a new write scope that includes reading
* Default scope for new ``provider.oauth2.models.AccessToken`` is now ``provider.constants.SCOPES[0][0]``
* Access token response returns a space seperated list of scopes instead of an integer value