"""
Default model implementations. Custom database or OAuth backends need to
implement these models with fields and and methods to be compatible with the
views in :attr:`provider.views`.
"""

from django.db import models
from django.conf import settings
from provider import constants
from provider.constants import CLIENT_TYPES
from provider.utils import now, short_token, long_token, get_code_expiry
from provider.utils import get_token_expiry

from django.utils import timezone


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

    Clients are outlined in the :rfc:`2` and its subsections.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, models.DO_NOTHING, related_name='oauth2_client',
        blank=True, null=True)
    name = models.CharField(max_length=255, blank=True)
    url = models.URLField(help_text="Your application's URL.")
    redirect_uri = models.URLField(help_text="Your application's callback URL")
    client_id = models.CharField(max_length=255, default=short_token)
    client_secret = models.CharField(max_length=255, default=long_token)
    client_type = models.IntegerField(choices=CLIENT_TYPES)
    auto_authorize = models.BooleanField(default=False, blank=True)
    authorize_every_time = models.BooleanField(default=False, blank=True)
    allow_public_token = models.BooleanField(default=False, blank=True,
                                             help_text="Allow public client tokens with only client_id and code")

    def __unicode__(self):
        return self.redirect_uri

    def get_default_token_expiry(self):
        public = (self.client_type == constants.PUBLIC)
        return get_token_expiry(public)

    class Meta:
        app_label = 'oauth2'
        db_table = 'oauth2_client'


class Scope(models.Model):
    name = models.CharField(max_length=50, primary_key=True)
    description = models.CharField(max_length=256, default='', blank=True)

    def __unicode__(self):
        return self.name

    class Meta:
        app_label = 'oauth2'
        db_table = 'oauth2_scope'


class AuthorizedClientManager(models.Manager):
    def get_authorization(self, user, client):
        return self.get(user=user, client=client)

    def check_authorization_scope(self, user, client, scope_list):
        try:
            authorization = self.get_authorization(user, client)
        except AuthorizedClient.DoesNotExist:
            return None
        authorized_scopes = {s.name for s in authorization.scope.all()}
        if set(scope_list) <= authorized_scopes:
            return authorization
        return None

    def set_authorization_scope(self, user, client, scope_list):
        try:
            authorization = self.get_authorization(user, client)
        except AuthorizedClient.DoesNotExist:
            authorization = self.create(user=user, client=client)
            authorization.save()
        for s in scope_list:
            authorization.scope.add(s)
        return authorization


class AuthorizedClient(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, models.DO_NOTHING,
                             related_name='oauth2_authorized_client')
    client = models.ForeignKey('Client', models.DO_NOTHING)
    scope = models.ManyToManyField('Scope')
    authorized_at = models.DateTimeField(auto_now_add=True, blank=True)

    objects = AuthorizedClientManager()

    class Meta:
        app_label = 'oauth2'
        db_table = 'oauth2_authorizedclient'
        unique_together = ['user', 'client']


class Grant(models.Model):
    """
    Default grant implementation. A grant is a code that can be swapped for an
    access token. Grants have a limited lifetime as defined by
    :attr:`provider.constants.EXPIRE_CODE_DELTA` and outlined in
    :rfc:`4.1.2`

    Expected fields:

    * :attr:`user`
    * :attr:`client` - :class:`Client`
    * :attr:`code`
    * :attr:`expires` - :attr:`datetime.datetime`
    * :attr:`redirect_uri`
    * :attr:`scope`
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, models.DO_NOTHING)
    client = models.ForeignKey('Client', models.DO_NOTHING)
    code = models.CharField(max_length=255, default=long_token)
    expires = models.DateTimeField(default=get_code_expiry)
    redirect_uri = models.CharField(max_length=255, blank=True)
    scope = models.ManyToManyField('Scope')

    def __unicode__(self):
        return self.code

    class Meta:
        app_label = 'oauth2'
        db_table = 'oauth2_grant'


class AccessTokenManager(models.Manager):
    def get_token(self, token):
        return self.get(token=token, expires__gt=now())

    def get_scoped_token(self, user, client, scope):
        obj = self.get(user=user, client=client, expires__gt=now())
        obj_scopes = {s.name for s in obj.scope.all()}
        req_scopes = {s.name for s in scope}
        if set(req_scopes).issubset(obj_scopes):
            return obj
        raise AccessToken.DoesNotExist

    def create(self, scope=None, *args, **kwargs):
        obj = super(AccessTokenManager, self).create(*args, **kwargs)
        obj.save()
        if not scope:
            scope = list()
        for s in scope:
            obj.scope.add(s)
        return obj


class AccessToken(models.Model):
    """
    Default access token implementation. An access token is a time limited
    token to access a user's resources.

    Access tokens are outlined :rfc:`5`.

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
    user = models.ForeignKey(settings.AUTH_USER_MODEL, models.DO_NOTHING)
    token = models.CharField(max_length=255, default=long_token, db_index=True)
    client = models.ForeignKey('Client', models.DO_NOTHING)
    expires = models.DateTimeField()
    scope = models.ManyToManyField('Scope')

    objects = AccessTokenManager()

    def __unicode__(self):
        return self.token

    def save(self, *args, **kwargs):
        if not self.expires:
            self.expires = self.client.get_default_token_expiry()
        super(AccessToken, self).save(*args, **kwargs)

    def get_expire_delta(self, reference=None):
        """
        Return the number of seconds until this token expires.
        """
        if reference is None:
            reference = now()
        expiration = self.expires

        if timezone:
            if timezone.is_aware(reference) and timezone.is_naive(expiration):
                # MySQL doesn't support timezone for datetime fields
                # so we assume that the date was stored in the UTC timezone
                expiration = timezone.make_aware(expiration, timezone.utc)
            elif timezone.is_naive(reference) and timezone.is_aware(expiration):
                reference = timezone.make_aware(reference, timezone.utc)

        timedelta = expiration - reference
        return timedelta.days*86400 + timedelta.seconds

    def get_scope_string(self):
        names = [s.name for s in self.scope.all()]
        names.sort()
        return ' '.join(names)

    class Meta:
        app_label = 'oauth2'
        db_table = 'oauth2_accesstoken'


class RefreshTokenManager(models.Manager):
    def create(self, scope=None, *args, **kwargs):
        obj = super(RefreshTokenManager, self).create(*args, **kwargs)
        obj.save()
        if not scope:
            scope = list()
        for s in scope:
            obj.scope.add(s)
        return obj


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
    user = models.ForeignKey(settings.AUTH_USER_MODEL, models.DO_NOTHING)
    token = models.CharField(max_length=255, default=long_token)
    access_token = models.OneToOneField('AccessToken', models.DO_NOTHING,
            related_name='refresh_token')
    client = models.ForeignKey('Client', models.DO_NOTHING)
    expired = models.BooleanField(default=False)

    objects = RefreshTokenManager()

    def __unicode__(self):
        return self.token

    class Meta:
        app_label = 'oauth2'
        db_table = 'oauth2_refreshtoken'
