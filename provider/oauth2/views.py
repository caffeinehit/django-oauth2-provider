from datetime import timedelta
from django.utils.timezone import now
from django.core.urlresolvers import reverse
from ..views import Capture, Authorize, Redirect
from ..views import AccessToken as AccessTokenView, OAuthError
from .forms import AuthorizationRequestForm, AuthorizationForm
from .forms import PasswordGrantForm, RefreshTokenGrantForm
from .forms import AuthorizationCodeGrantForm
from .models import Client, RefreshToken, AccessToken
from .backends import BasicClientBackend, RequestParamsClientBackend


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
        grant.expires = now() - timedelta(days=1)
        grant.save()

    def invalidate_refresh_token(self, rt):
        rt.expired = True
        rt.save()

    def invalidate_access_token(self, at):
        at.expires = now() - timedelta(days=1)
        at.save()
