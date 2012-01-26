from datetime import datetime
from django.contrib.auth.models import User
from django.db import models
from provider.constants import CLIENT_TYPES, SCOPES
from provider.oauth2.managers import AccessTokenManager
from provider.utils import short_token, long_token, get_token_expiry, \
    get_code_expiry


class Client(models.Model):
    user = models.ForeignKey(User)
    url = models.URLField(help_text="Your application's URL.")
    redirect_uri = models.URLField(help_text="Your application's callback URL")
    client_id = models.CharField(max_length=255, default=short_token)
    client_secret = models.CharField(max_length=255, default=long_token)
    client_type = models.IntegerField(choices=CLIENT_TYPES)
    
    def __unicode__(self):
        return self.redirect_uri

class Grant(models.Model):
    user = models.ForeignKey(User)
    client = models.ForeignKey(Client)
    code = models.CharField(max_length=255, default=long_token)
    expires = models.DateTimeField(default=get_code_expiry)
    redirect_uri = models.CharField(max_length=255, blank=True)
    scope = models.IntegerField(default=0)
    
    def __unicode__(self):
        return self.code
    
class AccessToken(models.Model):
    user = models.ForeignKey(User)
    token = models.CharField(max_length=255, default=short_token)
    client = models.ForeignKey(Client)
    expires = models.DateTimeField(default=get_token_expiry)
    scope = models.IntegerField(default=0)

    objects = AccessTokenManager()
    
    def __unicode__(self):
        return self.token
    
    def get_expire_delta(self):
        return (self.expires - datetime.now()).seconds

class RefreshToken(models.Model):
    user = models.ForeignKey(User)
    token = models.CharField(max_length=255, default=long_token)
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token')
    client = models.ForeignKey(Client)
    expired = models.BooleanField(default=False)
    
    def __unicode__(self):
        return self.token
