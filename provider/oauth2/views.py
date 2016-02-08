from datetime import timedelta
import json

from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.http import HttpResponseBadRequest, HttpResponse
from django.views.generic import View

from provider import constants
from provider.oauth2.backends import BasicClientBackend, RequestParamsClientBackend, PublicPasswordBackend
from provider.oauth2.forms import (AuthorizationCodeGrantForm, AuthorizationRequestForm, AuthorizationForm,
                                   PasswordGrantForm, RefreshTokenGrantForm, ClientCredentialsGrantForm)
from provider.oauth2.models import Client, RefreshToken, AccessToken
from provider.utils import now
from provider.views import AccessToken as AccessTokenView, OAuthError, AccessTokenMixin, Capture, Authorize, Redirect


class OAuth2AccessTokenMixin(AccessTokenMixin):

    def get_access_token(self, request, user, scope, client):
        try:
            # Attempt to fetch an existing access token.
            at = AccessToken.objects.get(user=user, client=client, scope=scope, expires__gt=now())
        except AccessToken.DoesNotExist:
            # None found... make a new one!
            at = self.create_access_token(request, user, scope, client)
        return at

    def create_access_token(self, request, user, scope, client):
        return AccessToken.objects.create(
            user=user,
            client=client,
            scope=scope
        )

    def create_refresh_token(self, request, user, scope, access_token, client):
        return RefreshToken.objects.create(
            user=user,
            access_token=access_token,
            client=client
        )

    def invalidate_refresh_token(self, rt):
        if constants.DELETE_EXPIRED:
            rt.delete()
        else:
            rt.expired = True
            rt.save()

    def invalidate_access_token(self, at):
        if constants.DELETE_EXPIRED:
            at.delete()
        else:
            at.expires = now() - timedelta(milliseconds=1)
            at.save()



class Capture(Capture):
    """
    Implementation of :class:`provider.views.Capture`.
    """

    def get_redirect_url(self, request):
        return reverse('oauth2:authorize')


class Authorize(Authorize, OAuth2AccessTokenMixin):
    """
    Implementation of :class:`provider.views.Authorize`.
    """

    def get_request_form(self, client, data):
        return AuthorizationRequestForm(data, client=client)

    def get_authorization_form(self, request, client, data, client_data):
        return AuthorizationForm(data)

    def get_client(self, client_id):
        try:
            return Client.objects.get(client_id=client_id)
        except Client.DoesNotExist:
            return None

    def get_redirect_url(self, request):
        return reverse('oauth2:redirect')

    def save_authorization(self, request, client, form, client_data):

        grant = form.save(commit=False)

        if grant is None:
            return None

        grant.user = request.user
        grant.client = client
        grant.redirect_uri = client_data.get('redirect_uri', '')
        grant.save()
        return grant.code


class Redirect(Redirect):
    """
    Implementation of :class:`provider.views.Redirect`
    """
    pass


class AccessTokenView(AccessTokenView, OAuth2AccessTokenMixin):
    """
    Implementation of :class:`provider.views.AccessToken`.

    .. note:: This implementation does provide all default grant types defined
        in :attr:`provider.views.AccessToken.grant_types`. If you
        wish to disable any, you can override the :meth:`get_handler` method
        *or* the :attr:`grant_types` list.
    """
    authentication = (
        BasicClientBackend,
        RequestParamsClientBackend,
        PublicPasswordBackend,
    )

    def get_authorization_code_grant(self, request, data, client):
        form = AuthorizationCodeGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data.get('grant')

    def get_refresh_token_grant(self, request, data, client):
        form = RefreshTokenGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data.get('refresh_token')

    def get_password_grant(self, request, data, client):
        form = PasswordGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data

    def get_client_credentials_grant(self, request, data, client):
        form = ClientCredentialsGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data

    def invalidate_grant(self, grant):
        if constants.DELETE_EXPIRED:
            grant.delete()
        else:
            grant.expires = now() - timedelta(days=1)
            grant.save()


class AccessTokenDetailView(View):
    """
    This view returns info about a given access token. If the token does not exist or is expired, HTTP 400 is returned.

    A successful response has HTTP status 200 and includes a JSON object containing the username, scope, and expiration
     date-time (in ISO 8601 format, UTC timezone) for the access token.

    Example
        GET /access_token/abc123/

        {
            username: "some-user",
            scope: "read",
            expires: "2015-04-01T08:41:51"
        }
    """

    def get(self, request, *args, **kwargs):
        JSON_CONTENT_TYPE = 'application/json'

        try:
            access_token = AccessToken.objects.get_token(kwargs['token'])
            content = {
                'username': access_token.user.username,
                'scope': access_token.get_scope_display(),
                'expires': access_token.expires.isoformat()
            }
            return HttpResponse(json.dumps(content), content_type=JSON_CONTENT_TYPE)
        except ObjectDoesNotExist:
            return HttpResponseBadRequest(json.dumps({'error': 'invalid_token'}), content_type=JSON_CONTENT_TYPE)
