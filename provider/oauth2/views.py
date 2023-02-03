from datetime import timedelta
from django.shortcuts import reverse
from provider import constants
from provider.views import CaptureViewBase, AuthorizeViewBase, RedirectViewBase
from provider.views import AccessTokenViewBase, OAuthError
from provider.utils import now
from provider.oauth2 import forms
from provider.oauth2 import models
from provider.oauth2 import backends

class CaptureView(CaptureViewBase):
    """
    Implementation of :class:`provider.views.Capture`.
    """

    def validate_scopes(self, scope_list):
        scopes = {s.name for s in
                  models.Scope.objects.filter(name__in=scope_list)}
        return set(scope_list).issubset(scopes)

    def get_redirect_url(self, request):
        return reverse('oauth2:authorize')


class AuthorizeView(AuthorizeViewBase):
    """
    Implementation of :class:`provider.views.Authorize`.
    """
    def get_request_form(self, client, data):
        return forms.AuthorizationRequestForm(data, client=client)

    def get_authorization_form(self, request, client, data, client_data):
        return forms.AuthorizationForm(data)

    def get_client(self, client_id):
        try:
            return models.Client.objects.get(client_id=client_id)
        except models.Client.DoesNotExist:
            return None

    def get_redirect_url(self, request):
        return reverse('oauth2:redirect')

    def has_authorization(self, request, client, scope_list):
        if client.auto_authorize:
            return True
        if client.authorize_every_time:
            return False

        authclient_mgr = models.AuthorizedClient.objects
        auth = authclient_mgr.check_authorization_scope(request.user,
                                                        client,
                                                        scope_list)
        return bool(auth)

    def save_authorization(self, request, client, form, client_data):

        scope_list = {s for s in form.cleaned_data['scope']}
        models.AuthorizedClient.objects.set_authorization_scope(request.user,
                                                                client,
                                                                scope_list)

        grant = form.save(user=request.user,
                          client=client,
                          redirect_uri=client_data.get('redirect_uri', ''))

        if grant is None:
            return None

        grant.user = request.user
        grant.client = client
        grant.redirect_uri = client_data.get('redirect_uri', '')
        grant.save()
        return grant.code


class RedirectView(RedirectViewBase):
    """
    Implementation of :class:`provider.views.Redirect`
    """
    pass


class AccessTokenView(AccessTokenViewBase):
    """
    Implementation of :class:`provider.views.AccessToken`.

    .. note:: This implementation does provide all default grant types defined
        in :attr:`provider.views.AccessToken.grant_types`. If you
        wish to disable any, you can override the :meth:`get_handler` method
        *or* the :attr:`grant_types` list.
    """
    authentication = (
        backends.BasicClientBackend,
        backends.RequestParamsClientBackend,
        backends.PublicPasswordBackend,
        backends.PublicClientBackend,
    )

    def get_authorization_code_grant(self, request, data, client):
        form = forms.AuthorizationCodeGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data.get('grant')

    def get_refresh_token_grant(self, request, data, client):
        form = forms.RefreshTokenGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data.get('refresh_token')

    def get_password_grant(self, request, data, client):
        form = forms.PasswordGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data

    def get_access_token(self, request, user, scope, client):
        try:
            # Attempt to fetch an existing access token.
            at = models.AccessToken.objects.get_scoped_token(user, client, scope)
        except models.AccessToken.DoesNotExist:
            # None found... make a new one!
            at = self.create_access_token(request, user, scope, client)
            if client.client_type != constants.PUBLIC:
                self.create_refresh_token(request, user, scope, at, client)
        return at

    def create_access_token(self, request, user, scope, client):
        at = models.AccessToken.objects.create(
            user=user,
            client=client,
        )
        for s in scope:
            at.scope.add(s)
        return at

    def create_refresh_token(self, request, user, scope, access_token, client):
        return models.RefreshToken.objects.create(
            user=user,
            access_token=access_token,
            client=client,
        )

    def invalidate_grant(self, grant):
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
