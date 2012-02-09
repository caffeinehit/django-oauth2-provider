"""
Default model implementations. Custom database or OAuth backends need to implement 
these models with fields and and methods to be compatible with the views in
:attr:`provider.views`.
"""

from datetime import datetime
from django.contrib.auth.models import User
from django.db import models
from provider.constants import CLIENT_TYPES, SCOPES
from provider.oauth2.managers import AccessTokenManager
from provider.utils import short_token, long_token, get_token_expiry, \
    get_code_expiry


class Client(models.Model):
    """
    Default client implementation.
    
    Expected fields:
    
    * :attr:`user`
    * :attr:`name`
    * :attr:`url`
    * :attr:`redirect_url`
    * :attr:`client_id`
    * :attr:`client_secret`
    * :attr:`client_type` 
    
    Clients are outlined in the :draft:`2` and its subsections.
    """
    user = models.ForeignKey(User, blank=True, null=True)
    name = models.CharField(max_length=255, blank=True)
    url = models.URLField(help_text="Your application's URL.")
    redirect_uri = models.URLField(help_text="Your application's callback URL")
    client_id = models.CharField(max_length=255, default=short_token)
    client_secret = models.CharField(max_length=255, default=long_token)
    client_type = models.IntegerField(choices=CLIENT_TYPES)
    
    def __unicode__(self):
        return self.redirect_uri

class Grant(models.Model):
    """
    Default grant implementation. A grant is a code that can be swapped for an
    access token. Grants have a limited lifetime as defined by 
    :attr:`provider.constants.EXPIRE_CODE_DELTA` and outlined in 
    :draft:`4.1.2`
    
    Expected fields:
    
    * :attr:`user`
    * :attr:`client` - :class:`Client`
    * :attr:`code`
    * :attr:`expires` - :attr:`datetime.datetime`
    * :attr:`redirect_uri`
    * :attr:`scope`
    """
    user = models.ForeignKey(User)
    client = models.ForeignKey(Client)
    code = models.CharField(max_length=255, default=long_token)
    expires = models.DateTimeField(default=get_code_expiry)
    redirect_uri = models.CharField(max_length=255, blank=True)
    scope = models.IntegerField(default=0)
    
    def __unicode__(self):
        return self.code
    
class AccessToken(models.Model):
    """
    Default access token implementation. An access token is a time limited token
    to access a user's resources.
    
    Access tokens are outlined :draft:`5`.
    
    Expected fields:
    
    * :attr:`user`
    * :attr:`token`
    * :attr:`client` - :class:`Client`
    * :attr:`expires` - :attr:`datetime.datetime`
    * :attr:`scope`
    
    Expected methods:

    * :meth:`get_expire_delta` - returns an integer representing seconds to
        expiry
    """
    user = models.ForeignKey(User)
    token = models.CharField(max_length=255, default=short_token)
    client = models.ForeignKey(Client)
    expires = models.DateTimeField(default=get_token_expiry)
    scope = models.IntegerField(default=0)

    objects = AccessTokenManager()
    
    def __unicode__(self):
        return self.token
    
    def get_expire_delta(self):
        """
        Return the number of seconds until this token expires.
        """
        return (self.expires - datetime.now()).seconds

class RefreshToken(models.Model):
    """
    Default refresh token implementation. A refresh token can be swapped for a
    new access token when said token expires.
    
    Expected fields:
    
    * :attr:`user`
    * :attr:`token`
    * :attr:`access_token` - :class:`AccessToken`
    * :attr:`client` - :class:`Client`
    * :attr:`expired` - ``boolean``
    """
    user = models.ForeignKey(User)
    token = models.CharField(max_length=255, default=long_token)
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token')
    client = models.ForeignKey(Client)
    expired = models.BooleanField(default=False)
    
    def __unicode__(self):
        return self.token
