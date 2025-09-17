import json
import logging
from datetime import timedelta
from urllib.parse import urlparse, ParseResult

from django.http import HttpResponse
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import reverse
from django.views.generic import TemplateView, View
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext as _

from provider import constants
from provider.utils import now, ArnHelper
from provider.oauth2 import forms
from provider.oauth2 import models
from provider.oauth2 import backends

log = logging.getLogger('provider.oauth2')


class OAuthError(Exception):
    """
    Exception to throw inside any views defined in :attr:`provider.views`.

    Any :attr:`OAuthError` thrown will be signalled to the API consumer.

    :attr:`OAuthError` expects a dictionary as its first argument outlining the
    type of error that occured.

    :example:

    ::

        raise OAuthError({'error': 'invalid_request'})

    The different types of errors are outlined in :rfc:`4.2.2.1` and
    :rfc:`5.2`.

    """


class AuthUtilMixin(object):
    """
    Mixin providing common methods required in the OAuth view defined in
    :attr:`provider.views`.
    """

    authentication = ()

    def get_data(self, request, key='params'):
        """
        Return stored data from the session store.

        :param key: `str` The key under which the data was stored.
        """
        return request.session.get('%s:%s' % (constants.SESSION_KEY, key))

    def cache_data(self, request, data, key='params'):
        """
        Cache data in the session store.

        :param request: :attr:`django.http.HttpRequest`
        :param data: Arbitrary data to store.
        :param key: `str` The key under which to store the data.
        """
        request.session['%s:%s' % (constants.SESSION_KEY, key)] = data

    def clear_data(self, request):
        """
        Clear all OAuth related data from the session store.
        """
        for key in list(request.session.keys()):
            if key.startswith(constants.SESSION_KEY):
                del request.session[key]

    def authenticate(self, request):
        """
        Authenticate a client against all the backends configured in
        :attr:`authentication`.
        """
        for backend in self.authentication:
            client = backend().authenticate(request)
            if client is not None:
                return client
        return None


class CaptureView(AuthUtilMixin, TemplateView):
    """
    As stated in section :rfc:`3.1.2.5` this view captures all the request
    parameters and redirects to another URL to avoid any leakage of request
    parameters to potentially harmful JavaScripts.

    This application assumes that whatever web-server is used as front-end will
    handle SSL transport.

    If you want strict enforcement of secure communication at application
    level, set :attr:`settings.OAUTH_ENFORCE_SECURE` to ``True``.

    """
    template_name = 'provider/authorize.html'


    def validate_scopes(self, scope_list):
        scopes = {s.name for s in
                  models.Scope.objects.filter(name__in=scope_list)}
        return set(scope_list).issubset(scopes)

    def get_redirect_url(self, request):
        return reverse('oauth2:authorize')

    def handle(self, request, data):
        self.cache_data(request, data)

        if constants.ENFORCE_SECURE and not request.is_secure():
            return self.render_to_response({'error': 'access_denied',
                'error_description': _("A secure connection is required."),
                'next': None},
                status=400)

        scope_list = [s for s in
                      data.get('scope', '').split(' ') if s != '']
        if self.validate_scopes(scope_list):
            return HttpResponseRedirect(self.get_redirect_url(request))
        else:
            return HttpResponse("Invalid scope.", status=400)

    def get(self, request, *args, **kwargs):
        return self.handle(request, request.GET)

    def post(self, request, *args, **kwargs):
        return self.handle(request, request.POST)


class AuthorizeView(AuthUtilMixin, TemplateView):
    """
    View to handle the client authorization as outlined in :rfc:`4`.

    :attr:`Authorize` renders the ``provider/authorize.html`` template to
    display the authorization form.

    On successful authorization, it redirects the user back to the defined
    client callback as defined in :rfc:`4.1.2`.

    On authorization fail :attr:`Authorize` displays an error message to the
    user with a modified redirect URL to the callback including the error
    and possibly description of the error as defined in :rfc:`4.1.2.1`.
    """

    template_name = 'provider/authorize.html'

    def get_request_form(self, client, data):
        if client.client_type == constants.PKCE:
            return forms.AuthorizationPkceRequestForm(data, client=client)
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
                          redirect_uri=client_data.get('redirect_uri', ''),
                          code_challenge=client_data.get('code_challenge'),
                          code_challenge_method=client_data.get('code_challenge_method'))

        if grant is None:
            return None

        return grant.code

    def _validate_client(self, request, data):
        """
        :return: ``tuple`` - ``(client or False, data or error)``
        """
        client = self.get_client(data.get('client_id'))

        if client is None:
            raise OAuthError({
                'error': 'unauthorized_client',
                'error_description': _("An unauthorized client tried to access"
                    " your resources.")
            })

        form = self.get_request_form(client, data)

        if not form.is_valid():
            raise OAuthError(form.errors)

        return client, form.cleaned_data

    def error_response(self, request, error, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes
        awry. Errors can include invalid clients, authorization denials and
        other edge cases such as a wrong ``redirect_uri`` in the authorization
        request.

        :param request: :attr:`django.http.HttpRequest`
        :param error: ``dict``
            The different types of errors are outlined in :rfc:`4.2.2.1`
        """
        ctx = {}
        ctx.update(error)

        # If we got a malicious redirect_uri or client_id, remove all the
        # cached data and tell the resource owner. We will *not* redirect back
        # to the URL.

        if error.get('error') in ['redirect_uri', 'unauthorized_client']:
            ctx.update(next='/')
            return self.render_to_response(ctx, **kwargs)

        ctx.update(next=self.get_redirect_url(request))

        return self.render_to_response(ctx, **kwargs)

    def handle(self, request, post_data=None):
        data = self.get_data(request)

        if data is None:
            return self.error_response(request, {
                'error': 'expired_authorization',
                'error_description': _('Authorization session has expired.')})

        try:
            client, data = self._validate_client(request, data)
        except OAuthError as e:
            return self.error_response(request, e.args[0], status=400)

        scope_list = [s.name for s in
                      data.get('scope', [])]
        if self.has_authorization(request, client, scope_list):
            post_data = {
                'scope': scope_list,
                'authorize': u'Authorize',
            }

        authorization_form = self.get_authorization_form(request, client,
                                                         post_data, data)

        if not authorization_form.is_bound or not authorization_form.is_valid():
            return self.render_to_response({
                'client': client,
                'form': authorization_form,
                'oauth_data': data,
            })

        code = self.save_authorization(request, client,
                                       authorization_form, data)

        # be sure to serialize any objects that aren't natively json
        # serializable because these values are stored as session data
        data['scope'] = scope_list
        data['client_id'] = client.client_id  # Add this back in, it gets lost sometimes
        self.cache_data(request, data)
        self.cache_data(request, code, "code")
        self.cache_data(request, client.pk, "client_pk")

        return HttpResponseRedirect(self.get_redirect_url(request))

    def get(self, request, *args, **kwargs):
        return self.handle(request, None)

    def post(self, request, *args, **kwargs):
        return self.handle(request, request.POST)




class RedirectView(AuthUtilMixin, View):
    """
    Redirect the user back to the client with the right query parameters set.
    This can be either parameters indicating success or parameters indicating
    an error.
    """

    def error_response(self, error, mimetype='application/json', status=400,
            **kwargs):
        """
        Return an error response to the client with default status code of
        *400* stating the error as outlined in :rfc:`5.2`.
        """
        return HttpResponse(json.dumps(error), content_type=mimetype,
                status=status, **kwargs)

    def get(self, request):
        data = self.get_data(request)
        code = self.get_data(request, "code")
        error = self.get_data(request, "error")
        client_pk = self.get_data(request, "client_pk")

        client = models.Client.objects.get(pk=client_pk)

        # this is an edge case that is caused by making a request with no data
        # it should only happen if this view is called manually, out of the
        # normal capture-authorize-redirect flow.
        if data is None or client is None:
            return self.error_response({
                'error': 'invalid_data',
                'error_description': _('Data has not been captured')})

        redirect_uri = data.get('redirect_uri', None) or client.redirect_uri

        parsed = urlparse(redirect_uri)

        query = QueryDict('', mutable=True)

        if 'state' in data:
            query['state'] = data['state']

        if error is not None:
            query.update(error)
        elif code is None:
            query['error'] = 'access_denied'
        else:
            query['code'] = code

        parsed = parsed[:4] + (query.urlencode(), '')

        redirect_uri = ParseResult(*parsed).geturl()

        self.clear_data(request)

        return HttpResponseRedirect(redirect_uri)


class AccessTokenView(AuthUtilMixin, TemplateView):
    """
    Implementation of :class:`provider.views.AccessToken`.

    .. note:: This implementation does provide all default grant types defined
        in :attr:`provider.views.AccessToken.grant_types`. If you
        wish to disable any, you can override the :meth:`get_handler` method
        *or* the :attr:`grant_types` list.


    According to :rfc:`4.4.2` this endpoint too must support secure
    communication. For strict enforcement of secure communication at
    application level set :attr:`settings.OAUTH_ENFORCE_SECURE` to ``True``.

    According to :rfc:`3.2` we can only accept POST requests.

    Returns with a status code of *400* in case of errors. *200* in case of
    success.

    """
    authentication = (
        backends.BasicClientBackend,
        backends.RequestParamsClientBackend,
        backends.PkceRequestParamsClientBackend,
        backends.PublicPasswordBackend,
        backends.PublicClientBackend,
    )

    grant_types = ['authorization_code', 'refresh_token', 'password', 'aws_identity']
    """
    The default grant types supported by this view.
    """

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

    def get_aws_grant(self, request, data, _client):
        form = forms.AwsGrantForm(data)
        if not form.is_valid():
            raise OAuthError(form.errors)
        data = form.cleaned_data
        arn = data.get('arn')
        try:
            account = models.AwsAccount.objects.get(
                account_id=arn.account_id,
                general_type=arn.general_type,
                name=arn.name,
            )
        except models.AwsAccount.DoesNotExist:
            log.info("No AwsAccount found for arn '%s'", arn.arn)
            raise OAuthError("not_authorized")

        data['awsaccount'] = account
        return data

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

    def error_response(self, error, mimetype='application/json', status=400,
            **kwargs):
        """
        Return an error response to the client with default status code of
        *400* stating the error as outlined in :rfc:`5.2`.
        """
        return HttpResponse(json.dumps(error), content_type=mimetype,
                status=status, **kwargs)

    def access_token_response(self, access_token):
        """
        Returns a successful response after creating the access token
        as defined in :rfc:`5.1`.
        """

        response_data = {
            'access_token': access_token.token,
            'token_type': constants.TOKEN_TYPE,
            'expires_in': access_token.get_expire_delta(),
            'scope': access_token.get_scope_string(),
        }

        # Not all access_tokens are given a refresh_token
        # (for example, public clients doing password auth)
        try:
            rt = access_token.refresh_token
            response_data['refresh_token'] = rt.token
        except ObjectDoesNotExist:
            pass

        return HttpResponse(
            json.dumps(response_data), content_type='application/json'
        )

    def authorization_code(self, request, data, client):
        """
        Handle ``grant_type=authorization_code`` requests as defined in
        :rfc:`4.1.3`.
        """
        grant = self.get_authorization_code_grant(request, request.POST,
                client)
        at = self.create_access_token(request, grant.user,
                                      list(grant.scope.all()), client)

        suppress_refresh_token = False
        if client.client_type == constants.PUBLIC and client.allow_public_token:
            if not request.POST.get('client_secret'):
                suppress_refresh_token = True

        if not suppress_refresh_token:
            rt = self.create_refresh_token(request, grant.user,
                                           list(grant.scope.all()), at, client)

        self.invalidate_grant(grant)

        return self.access_token_response(at)

    def refresh_token(self, request, data, client):
        """
        Handle ``grant_type=refresh_token`` requests as defined in :rfc:`6`.
        """
        rt = self.get_refresh_token_grant(request, data, client)

        token_scope = list(rt.access_token.scope.all())

        # this must be called first in case we need to purge expired tokens
        self.invalidate_refresh_token(rt)
        self.invalidate_access_token(rt.access_token)

        at = self.create_access_token(request, rt.user,
                                      token_scope,
                                      client)
        rt = self.create_refresh_token(request, at.user,
                                       at.scope.all(), at, client)

        return self.access_token_response(at)

    def password(self, request, data, client):
        """
        Handle ``grant_type=password`` requests as defined in :rfc:`4.3`.
        """

        data = self.get_password_grant(request, data, client)
        user = data.get('user')
        scope = data.get('scope')

        at = self.create_access_token(request, user, scope, client)
        # Public clients don't get refresh tokens
        if client.client_type != constants.PUBLIC:
            rt = self.create_refresh_token(request, user, scope, at, client)

        return self.access_token_response(at)

    def aws_identity(self, request, data, client):
        data = self.get_aws_grant(request, data, client)
        account = data.get('awsaccount')
        scope = list(account.scope.all())

        at = self.create_access_token(request, account.get_or_create_user(), scope, account.client)
        at.expires = now() + timedelta(seconds=account.max_token_lifetime)
        at.save()
        return self.access_token_response(at)

    def get_handler(self, grant_type):
        """
        Return a function or method that is capable handling the ``grant_type``
        requested by the client or return ``None`` to indicate that this type
        of grant type is not supported, resulting in an error response.
        """
        if grant_type == 'authorization_code':
            return self.authorization_code
        elif grant_type == 'refresh_token':
            return self.refresh_token
        elif grant_type == 'password':
            return self.password
        elif grant_type == 'aws_identity':
            return self.aws_identity
        return None

    def get(self, request, *args, **kwargs):
        """
        As per :rfc:`3.2` the token endpoint *only* supports POST requests.
        Returns an error response.
        """
        return self.error_response({
            'error': 'invalid_request',
            'error_description': _("Only POST requests allowed.")})

    def post(self, request):
        """
        As per :rfc:`3.2` the token endpoint *only* supports POST requests.
        """
        if constants.ENFORCE_SECURE and not request.is_secure():
            return self.error_response({
                'error': 'invalid_request',
                'error_description': _("A secure connection is required.")})

        if not 'grant_type' in request.POST:
            return self.error_response({
                'error': 'invalid_request',
                'error_description': _("No 'grant_type' included in the "
                    "request.")})

        grant_type = request.POST['grant_type']

        if grant_type not in self.grant_types:
            return self.error_response({'error': 'unsupported_grant_type'})

        client = self.authenticate(request)

        if client is None and grant_type != 'aws_identity':
            return self.error_response({'error': 'invalid_client'})

        handler = self.get_handler(grant_type)

        try:
            return handler(request, request.POST, client)
        except OAuthError as e:
            return self.error_response(e.args[0])
