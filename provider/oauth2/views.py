from datetime import timedelta
from django.core.urlresolvers import reverse
from .. import constants
from ..views import Capture, Authorize, Redirect
from ..views import AccessToken as AccessTokenView, OAuthError, Grant as GrantView
from ..utils import now
from .forms import AuthorizationRequestForm, AuthorizationForm
from .forms import PasswordGrantForm, RefreshTokenGrantForm
from .forms import AuthorizationCodeGrantForm
from .models import Client, RefreshToken, AccessToken, Grant
from .backends import BasicClientBackend, RequestParamsClientBackend, PublicPasswordBackend


class Capture(Capture):
    """
    Implementation of :class:`provider.views.Capture`.
    """
    def get_redirect_url(self, request):
        return reverse('oauth2:authorize')


class Authorize(Authorize):
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


class GrantView(GrantView):
    """
    Implementation of :class:`provider.views.Grant`
    """
    """
    Authenticate a user via access token and client object.
    """

    def authenticate(self, access_token=None, client=None):
        try:
            return AccessToken.objects.get(token=access_token,
                expires__gt=now())
        except AccessToken.DoesNotExist:
            return None

    def get_client(self, client_id):
        try:
            return Client.objects.get(client_id=client_id)
        except Client.DoesNotExist:
            return None

    def get_grant(self, user, client):
        scope = 2
        try:
            # Attempt to fetch an existing access token.
            g = Grant.objects.get(user_id=user.id, client=client, expires__gt=now())
        except Grant.DoesNotExist:
            # None found... make a new one!
            g = self.create_grant(user, scope, client)
        return g

    def create_grant(self, user, scope, client):
        return Grant.objects.create(
            user=user,
            client=client,
            scope=scope,
            expires=now() + constants.GRANT_EXPIRE_DELTA,
        )

    def list_grants(self, user):
        try:
          valid = Grant.objects.filter(user=user.id, expires__gt=now())

          if len(valid) == 0:
            return None

          return valid.values()
        except Grant.DoesNotExist:
          return None


class AccessTokenView(AccessTokenView):
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

    def get_access_token(self, request, user, scope, client):
        try:
            # Attempt to fetch an existing access token.
            at = AccessToken.objects.get(user=user, client=client,
                                         scope=scope, expires__gt=now())
        except AccessToken.DoesNotExist:
            # None found... make a new one!
            at = self.create_access_token(request, user, scope, client)
            self.create_refresh_token(request, user, scope, at, client)
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

    def invalidate_grant(self, grant):
        if not constants.LONG_LIVE_GRANT:
          if constants.DELETE_EXPIRED:
              grant.delete()
          else:
              grant.expires = now() - timedelta(days=1)
              grant.save()

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
            at.expires = now() - timedelta(days=1)
            at.save()
