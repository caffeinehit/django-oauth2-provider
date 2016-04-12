import datetime
import json
import urlparse

import ddt
from django.conf import settings
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.http import QueryDict
from django.test import TestCase
from django.utils.html import escape
from mock import patch

from provider import constants, scope
from provider.oauth2.backends import AccessTokenBackend, BasicClientBackend, RequestParamsClientBackend
from provider.oauth2.forms import ClientForm
from provider.oauth2.models import Client, Grant, AccessToken, RefreshToken
from provider.templatetags.scope import scopes
from provider.utils import now as date_now


class BaseOAuth2TestCase(TestCase):
    def login(self):
        self.client.login(username='test-user-1', password='test')

    def auth_url(self):
        return reverse('oauth2:capture')

    def auth_url2(self):
        return reverse('oauth2:authorize')

    def redirect_url(self):
        return reverse('oauth2:redirect')

    def access_token_url(self):
        return reverse('oauth2:access_token')

    def get_client(self):
        return Client.objects.get(id=2)

    def get_grant(self):
        return Grant.objects.all()[0]

    def get_user(self):
        return User.objects.get(id=1)

    def get_password(self):
        return 'test'

    def get_auth_params(self, response_type="code", **kwargs):
        kwargs.setdefault("client_id", self.get_client().client_id)
        if response_type:
            kwargs["response_type"] = response_type
        return kwargs

    def _login_and_authorize(self, url_func=None):
        if url_func is None:
            url_func = lambda: self.auth_url() + '?client_id={0}&response_type=code&state=abc'.format(
                self.get_client().client_id)

        response = self.client.get(url_func())
        response = self.client.get(self.auth_url2())

        response = self.client.post(self.auth_url2(), {'authorize': True, 'scope': constants.SCOPES[0][1]})
        self.assertEqual(302, response.status_code, response.content)
        self.assertTrue(self.redirect_url() in response['Location'])


@ddt.ddt
class AuthorizationTest(BaseOAuth2TestCase):
    fixtures = ['test_oauth2']

    def setUp(self):
        self._old_login = settings.LOGIN_URL
        settings.LOGIN_URL = '/login/'

    def tearDown(self):
        settings.LOGIN_URL = self._old_login

    def test_authorization_requires_login(self):
        response = self.client.get(self.auth_url())

        # Login redirect
        self.assertEqual(302, response.status_code)
        self.assertEqual('/login/', urlparse.urlparse(response['Location']).path)

        self.login()

        response = self.client.get(self.auth_url())

        self.assertEqual(302, response.status_code)

        self.assertTrue(self.auth_url2() in response['Location'])

    @ddt.data(
        ('read', 'read'),
        ('write', 'write'),
        ('read+write', 'read write read+write'),
    )
    @ddt.unpack
    def test_implicit_flow(self, requested_scope, expected_scope):
        """
        End-to-end test of the implicit flow (happy path).
        """
        self.login()
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type='token', scope=requested_scope))
        response = self.client.post(self.auth_url2(), {'authorize': True})
        fragment = urlparse.urlparse(response['Location']).fragment
        auth_response_data = {k: v[0] for k, v in urlparse.parse_qs(fragment).items()}
        self.assertEqual(auth_response_data['scope'], expected_scope)
        self.assertEqual(auth_response_data['access_token'], AccessToken.objects.all()[0].token)
        self.assertEqual(auth_response_data['token_type'], 'Bearer')
        self.assertEqual(int(auth_response_data['expires_in']), constants.EXPIRE_DELTA.days * 60 * 60 * 24 - 1)
        self.assertNotIn('refresh_token', response)

    @ddt.data('code', 'token')
    def test_authorization_requires_client_id(self, response_type):
        self.login()
        self.client.get(self.auth_url(), data={'response_type': response_type})
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertTrue("An unauthorized client tried to access your resources." in response.content)

    @ddt.data('code', 'token')
    def test_authorization_rejects_invalid_client_id(self, response_type):
        self.login()
        response = self.client.get(self.auth_url(), data={"client_id": 123, 'response_type': response_type})
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertTrue("An unauthorized client tried to access your resources." in response.content)

    def test_authorization_requires_response_type(self):
        self.login()
        response = self.client.get(self.auth_url(), data=self.get_auth_params(response_type=None))
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertTrue(escape(u"No 'response_type' supplied.") in response.content)

    @ddt.data('code', 'token', 'unsupported')
    def test_authorization_requires_supported_response_type(self, response_type):
        self.login()
        response = self.client.get(
            self.auth_url(), self.get_auth_params(response_type=response_type))
        response = self.client.get(self.auth_url2())

        if response_type == 'unsupported':
            self.assertEqual(400, response.status_code)
            self.assertTrue(escape(u"'unsupported' is not a supported response type.") in response.content)

        else:
            self.assertEqual(200, response.status_code)

    def test_token_authorization_redirects_to_correct_uri(self):
        self.login()

        response1 = self.client.get(self.auth_url(), data=self.get_auth_params(response_type="token"), follow=True)

        # confirm the resulting "do you agree" section.
        # We can skip the csrf mapping during tests.
        response2 = self.client.post(self.auth_url2(), data={'authorize': 'Authorize'})

        self.assertEqual(302, response2.status_code)
        url, fragment = response2.get('location').split('#')
        self.assertEqual(url, self.get_client().redirect_uri)
        self.assertTrue('access_token' in urlparse.parse_qs(fragment))

    @patch('provider.constants.SINGLE_ACCESS_TOKEN', True)
    def test_token_ignores_expired_tokens(self):
        AccessToken.objects.create(
            user=self.get_user(),
            client=self.get_client(),
            expires=date_now() - datetime.timedelta(days=1),
        )

        self.login()
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type="token"))
        self.client.post(self.auth_url2(), data={'authorize': 'Authorize'})

        self.assertEqual(AccessToken.objects.count(), 2)

    @patch('provider.constants.SINGLE_ACCESS_TOKEN', True)
    def test_token_doesnt_return_tokens_from_another_client(self):
        # Different client than we'll be submitting an RPC for.
        AccessToken.objects.create(
            user=self.get_user(),
            client=Client.objects.get(pk=1)
        )

        self.login()
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type="token"))
        self.client.post(self.auth_url2(), data={'authorize': 'Authorize'})

        self.assertEqual(AccessToken.objects.count(), 2)

    @patch('provider.constants.SINGLE_ACCESS_TOKEN', True)
    def test_token_authorization_respects_single_access_token_constant(self):
        self.login()
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type="token"))
        self.client.post(self.auth_url2(), data={'authorize': 'Authorize'})

        self.assertEqual(AccessToken.objects.count(), 1)

        # Second request.
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type="token"))
        self.client.post(self.auth_url2(), data={'authorize': 'Authorize'})

        self.assertEqual(AccessToken.objects.count(), 1)

    @patch('provider.constants.SINGLE_ACCESS_TOKEN', False)
    def test_token_authorization_can_do_multi_access_tokens(self):
        self.login()
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type="token"))
        self.client.post(self.auth_url2(), data={'authorize': 'Authorize'})

        self.assertEqual(AccessToken.objects.count(), 1)

        # Second request.
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type="token"))
        self.client.post(self.auth_url2(), data={'authorize': 'Authorize'})

        self.assertEqual(AccessToken.objects.count(), 2)

    @patch('provider.constants.SINGLE_ACCESS_TOKEN', False)
    def test_token_authorization_cancellation(self):
        self.login()
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type="token"))
        self.client.post(self.auth_url2())

        self.assertEqual(AccessToken.objects.count(), 0)

    @ddt.data('code', 'token')
    def test_authorization_requires_a_valid_redirect_uri(self, response_type):
        self.login()

        self.client.get(
            self.auth_url(),
            data=self.get_auth_params(
                response_type=response_type, redirect_uri=self.get_client().redirect_uri + '-invalid'
            )
        )
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertTrue(escape(u"The requested redirect didn't match the client settings.") in response.content)

        self.client.get(self.auth_url(), data=self.get_auth_params(
            response_type=response_type, redirect_uri=self.get_client().redirect_uri))
        response = self.client.get(self.auth_url2())

        self.assertEqual(200, response.status_code)

    @ddt.data('code', 'token')
    def test_authorization_requires_a_valid_scope(self, response_type):
        self.login()

        self.client.get(self.auth_url(), data=self.get_auth_params(response_type=response_type, scope="invalid"))
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertTrue(escape(u"'invalid' is not a valid scope.") in response.content,
                        'Expected `{0}` in {1}'.format(escape(u"'invalid' is not a valid scope."), response.content))

        self.client.get(
            self.auth_url(),
            data=self.get_auth_params(response_type=response_type, scope=constants.SCOPES[0][1])
        )
        response = self.client.get(self.auth_url2())
        self.assertEqual(200, response.status_code)

    @ddt.data('code', 'token')
    def test_authorization_sets_default_scope(self, response_type):

        self.login()
        self.client.get(self.auth_url(), data=self.get_auth_params(response_type=response_type))
        response = self.client.post(self.auth_url2(), {'authorize': True})

        if response_type == 'code':
            # authorization code flow
            response = self.client.get(self.redirect_url())
            query = urlparse.urlparse(response['Location']).query
            code = urlparse.parse_qs(query)['code'][0]
            response = self.client.post(self.access_token_url(), {
                'grant_type': 'authorization_code',
                'client_id': self.get_client().client_id,
                'client_secret': self.get_client().client_secret,
                'code': code})
            scope_str = json.loads(response.content).get('scope')
        else:
            # implicit flow
            fragment = urlparse.urlparse(response['Location']).fragment
            scope_str = urlparse.parse_qs(fragment)['scope'][0]

        self.assertEqual(scope_str, constants.SCOPES[0][1])

    @ddt.data('code', 'token')
    def test_authorization_is_not_granted(self, response_type):
        self.login()

        self.client.get(self.auth_url(), data=self.get_auth_params(response_type=response_type))
        self.client.get(self.auth_url2())

        response = self.client.post(self.auth_url2(), {'authorize': False, 'scope': constants.SCOPES[0][1]})
        self.assertEqual(302, response.status_code, response.content)
        self.assertTrue(self.get_client().redirect_uri in response['Location'],
                        '{0} not in {1}'.format(self.redirect_url(), response['Location']))
        self.assertTrue('error=access_denied' in response['Location'])
        self.assertFalse(response_type in response['Location'])

    def test_authorization_is_granted(self):
        self.login()

        self._login_and_authorize()

        response = self.client.get(self.redirect_url())

        self.assertEqual(302, response.status_code)
        self.assertFalse('error' in response['Location'])
        self.assertTrue('code' in response['Location'])

    def test_preserving_the_state_variable(self):
        self.login()

        self._login_and_authorize()

        response = self.client.get(self.redirect_url())

        self.assertEqual(302, response.status_code)
        self.assertFalse('error' in response['Location'])
        self.assertTrue('code' in response['Location'])
        self.assertTrue('state=abc' in response['Location'])

    def test_preserving_the_state_variable_implicit(self):
        self.login()

        self.client.get(self.auth_url(), data=self.get_auth_params(response_type='token', state='abc'))
        self.client.get(self.auth_url2())
        response = self.client.post(self.auth_url2(), {'authorize': True, 'scope': constants.SCOPES[0][1]})
        self.assertEqual(302, response.status_code)
        self.assertFalse('error' in response['Location'])
        self.assertTrue('access_token=' in response['Location'])
        self.assertTrue('state=abc' in response['Location'])

    def test_redirect_requires_valid_data(self):
        self.login()
        response = self.client.get(self.redirect_url())
        self.assertEqual(400, response.status_code)


class AccessTokenTest(BaseOAuth2TestCase):
    fixtures = ['test_oauth2.json']

    def test_access_token_get_expire_delta_value(self):
        user = self.get_user()
        client = self.get_client()
        token = AccessToken.objects.create(user=user, client=client)
        now = date_now()
        default_expiration_timedelta = constants.EXPIRE_DELTA
        current_expiration_timedelta = datetime.timedelta(seconds=token.get_expire_delta(reference=now))
        self.assertLessEqual(abs(current_expiration_timedelta - default_expiration_timedelta),
                             datetime.timedelta(seconds=1))

    def test_fetching_access_token_with_invalid_client(self):
        self.login()
        self._login_and_authorize()

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id + '123',
            'client_secret': self.get_client().client_secret, })

        self.assertEqual(400, response.status_code, response.content)
        self.assertEqual('invalid_client', json.loads(response.content)['error'])

    def test_fetching_access_token_with_invalid_grant(self):
        self.login()
        self._login_and_authorize()

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': '123'})

        self.assertEqual(400, response.status_code, response.content)
        self.assertEqual('invalid_grant', json.loads(response.content)['error'])

    def _login_authorize_get_token(self):
        required_props = ['access_token', 'token_type']

        self.login()
        self._login_and_authorize()

        response = self.client.get(self.redirect_url())
        query = QueryDict(urlparse.urlparse(response['Location']).query)
        code = query['code']

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code})

        self.assertEqual(200, response.status_code, response.content)

        token = json.loads(response.content)

        for prop in required_props:
            self.assertIn(prop, token, "Access token response missing required property: %s" % prop)

        return token

    def test_fetching_access_token_with_valid_grant(self):
        self._login_authorize_get_token()

    def test_fetching_access_token_with_invalid_grant_type(self):
        self.login()
        self._login_and_authorize()
        response = self.client.get(self.redirect_url())

        query = QueryDict(urlparse.urlparse(response['Location']).query)
        code = query['code']

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'invalid_grant_type',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code
        })

        self.assertEqual(400, response.status_code)
        self.assertEqual('unsupported_grant_type', json.loads(response.content)['error'], response.content)

    @patch('provider.constants.SINGLE_ACCESS_TOKEN', True)
    def test_fetching_single_access_token(self):
        result1 = self._login_authorize_get_token()
        result2 = self._login_authorize_get_token()

        self.assertEqual(result1['access_token'], result2['access_token'])

    def test_fetching_single_access_token_after_refresh(self):
        token = self._login_authorize_get_token()

        self.client.post(self.access_token_url(), {
            'grant_type': 'refresh_token',
            'refresh_token': token['refresh_token'],
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
        })

        new_token = self._login_authorize_get_token()
        self.assertNotEqual(token['access_token'], new_token['access_token'])

    def test_fetching_access_token_multiple_times(self):
        self._login_authorize_get_token()
        code = self.get_grant().code

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code})

        self.assertEqual(400, response.status_code)
        self.assertEqual('invalid_grant', json.loads(response.content)['error'])

    def test_escalating_the_scope(self):
        self.login()
        self._login_and_authorize()
        code = self.get_grant().code

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code,
            'scope': 'read write'})

        self.assertEqual(400, response.status_code)
        self.assertEqual('invalid_scope', json.loads(response.content)['error'])

    def test_refreshing_an_access_token(self):
        token = self._login_authorize_get_token()

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'refresh_token',
            'refresh_token': token['refresh_token'],
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
        })

        self.assertEqual(200, response.status_code)

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'refresh_token',
            'refresh_token': token['refresh_token'],
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
        })

        self.assertEqual(400, response.status_code)
        self.assertEqual('invalid_grant', json.loads(response.content)['error'], response.content)

    def test_password_grant_public(self):
        c = self.get_client()
        c.client_type = 1  # public
        c.save()

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'password',
            'client_id': c.client_id,
            # No secret needed
            'username': self.get_user().username,
            'password': self.get_password(),
        })

        self.assertEqual(200, response.status_code, response.content)
        self.assertNotIn('refresh_token', json.loads(response.content))
        expires_in = json.loads(response.content)['expires_in']
        expires_in_days = round(expires_in / (60.0 * 60.0 * 24.0))
        self.assertEqual(expires_in_days, constants.EXPIRE_DELTA_PUBLIC.days)

    def test_password_grant_confidential(self):
        c = self.get_client()
        c.client_type = constants.CONFIDENTIAL
        c.save()

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'password',
            'client_id': c.client_id,
            'client_secret': c.client_secret,
            'username': self.get_user().username,
            'password': self.get_password(),
        })

        self.assertEqual(200, response.status_code, response.content)
        self.assertTrue(json.loads(response.content)['refresh_token'])

    def test_password_grant_confidential_no_secret(self):
        c = self.get_client()
        c.client_type = 0  # confidential
        c.save()

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'password',
            'client_id': c.client_id,
            'username': self.get_user().username,
            'password': self.get_password(),
        })

        self.assertEqual('invalid_client', json.loads(response.content)['error'])

    def test_password_grant_invalid_password_public(self):
        c = self.get_client()
        c.client_type = 1  # public
        c.save()

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'password',
            'client_id': c.client_id,
            'username': self.get_user().username,
            'password': self.get_password() + 'invalid',
        })

        self.assertEqual(400, response.status_code, response.content)
        self.assertEqual('invalid_client', json.loads(response.content)['error'])

    def test_password_grant_invalid_password_confidential(self):
        c = self.get_client()
        c.client_type = 0  # confidential
        c.save()

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'password',
            'client_id': c.client_id,
            'client_secret': c.client_secret,
            'username': self.get_user().username,
            'password': self.get_password() + 'invalid',
        })

        self.assertEqual(400, response.status_code, response.content)
        self.assertEqual('invalid_grant', json.loads(response.content)['error'])

    def test_access_token_response_valid_token_type(self):
        token = self._login_authorize_get_token()
        self.assertEqual(token['token_type'], constants.TOKEN_TYPE, token)


@ddt.ddt
class ClientCredentialsAccessTokenTests(BaseOAuth2TestCase):
    """ Tests for issuing access tokens using the client credentials grant. """
    fixtures = ['test_oauth2.json']

    def setUp(self):
        super(ClientCredentialsAccessTokenTests, self).setUp()
        AccessToken.objects.all().delete()

    def request_access_token(self, client_id=None, client_secret=None, scope=None):
        """ Issues an access token request using the client credentials grant.

        Arguments:
            client_id (str): Optional override of the client ID credential.
            client_secret (str): Optional override of the client secret credential.

        Returns:
            HttpResponse
        """
        client = self.get_client()
        data = {
            'grant_type': 'client_credentials',
            'client_id': client_id or client.client_id,
            'client_secret': client_secret or client.client_secret,
        }

        if scope:
            data.update({
                'scope': scope,
            })

        return self.client.post(self.access_token_url(), data)

    def assert_valid_access_token_response(self, access_token, response):
        """ Verifies the content of the response contains a JSON representation of the access token.

        Note:
            The access token should NOT have an associated refresh token.
        """
        expected = {
            u'access_token': access_token.token,
            u'token_type': constants.TOKEN_TYPE,
            u'expires_in': access_token.get_expire_delta(),
            u'scope': u' '.join(scope.names(access_token.scope)),
        }

        self.assertEqual(json.loads(response.content), expected)

    def get_latest_access_token(self):
        return AccessToken.objects.filter(client=self.get_client()).order_by('-id')[0]

    @ddt.data(None, 'read')
    def test_authorize_success(self, scope):
        """ Verify the endpoint successfully issues an access token using the client credentials grant. """
        response = self.request_access_token(scope=scope)
        self.assertEqual(200, response.status_code, response.content)

        access_token = self.get_latest_access_token()
        self.assert_valid_access_token_response(access_token, response)

    @ddt.data(
        {'client_id': 'invalid'},
        {'client_secret': 'invalid'},
    )
    def test_authorize_with_invalid_credentials(self, credentials_override):
        """ Verify the endpoint returns HTTP 400 if the credentials are invalid. """
        response = self.request_access_token(**credentials_override)
        self.assertEqual(400, response.status_code, response.content)
        self.assertDictEqual(json.loads(response.content), {'error': 'invalid_client'})


class AuthBackendTest(BaseOAuth2TestCase):
    fixtures = ['test_oauth2']

    def test_basic_client_backend(self):
        request = type('Request', (object,), {'META': {}})()
        request.META['HTTP_AUTHORIZATION'] = "Basic " + "{0}:{1}".format(
            self.get_client().client_id,
            self.get_client().client_secret).encode('base64')

        self.assertEqual(BasicClientBackend().authenticate(request).id,
                         2, "Didn't return the right client.")

    def test_request_params_client_backend(self):
        request = type('Request', (object,), {'REQUEST': {}})()

        request.REQUEST['client_id'] = self.get_client().client_id
        request.REQUEST['client_secret'] = self.get_client().client_secret

        self.assertEqual(RequestParamsClientBackend().authenticate(request).id,
                         2, "Didn't return the right client.'")

    def test_access_token_backend(self):
        user = self.get_user()
        client = self.get_client()
        backend = AccessTokenBackend()
        token = AccessToken.objects.create(user=user, client=client)
        authenticated = backend.authenticate(access_token=token.token, client=client)

        self.assertIsNotNone(authenticated)


class EnforceSecureTest(BaseOAuth2TestCase):
    fixtures = ['test_oauth2']

    def setUp(self):
        constants.ENFORCE_SECURE = True

    def tearDown(self):
        constants.ENFORCE_SECURE = False

    def test_authorization_enforces_SSL(self):
        self.login()

        response = self.client.get(self.auth_url())

        self.assertEqual(400, response.status_code)
        self.assertTrue("A secure connection is required." in response.content)

    def test_access_token_enforces_SSL(self):
        response = self.client.post(self.access_token_url(), {})

        self.assertEqual(400, response.status_code)
        self.assertTrue("A secure connection is required." in response.content)


class ClientFormTest(TestCase):
    def test_client_form(self):
        form = ClientForm({'name': 'TestName', 'url': 'http://127.0.0.1:8000',
                           'redirect_uri': 'http://localhost:8000/'})

        self.assertFalse(form.is_valid())

        form = ClientForm({
            'name': 'TestName',
            'url': 'http://127.0.0.1:8000',
            'redirect_uri': 'http://localhost:8000/',
            'client_type': constants.CLIENT_TYPES[0][0]})
        self.assertTrue(form.is_valid())
        form.save()


class ScopeTest(TestCase):
    def setUp(self):
        self._scopes = constants.SCOPES
        constants.SCOPES = constants.DEFAULT_SCOPES

    def tearDown(self):
        constants.SCOPES = self._scopes

    def test_get_scope_names(self):
        names = scope.to_names(constants.READ)
        self.assertEqual('read', ' '.join(names))

        names = scope.names(constants.READ_WRITE)
        names.sort()

        self.assertEqual('read read+write write', ' '.join(names))

    def test_get_scope_ints(self):
        self.assertEqual(constants.READ, scope.to_int('read'))
        self.assertEqual(constants.WRITE, scope.to_int('write'))
        self.assertEqual(constants.READ_WRITE, scope.to_int('read', 'write'))
        self.assertEqual(0, scope.to_int('invalid'))
        self.assertEqual(1, scope.to_int('invalid', default=1))

    def test_template_filter(self):
        names = scopes(constants.READ)
        self.assertEqual('read', ' '.join(names))

        names = scope.names(constants.READ_WRITE)
        names.sort()

        self.assertEqual('read read+write write', ' '.join(names))


class DeleteExpiredTest(BaseOAuth2TestCase):
    fixtures = ['test_oauth2']

    def setUp(self):
        self._delete_expired = constants.DELETE_EXPIRED
        constants.DELETE_EXPIRED = True

    def tearDown(self):
        constants.DELETE_EXPIRED = self._delete_expired

    def test_clear_expired(self):
        self.login()

        self._login_and_authorize()

        response = self.client.get(self.redirect_url())

        self.assertEqual(302, response.status_code)
        location = response['Location']
        self.assertFalse('error' in location)
        self.assertTrue('code' in location)

        # verify that Grant with code exists
        code = urlparse.parse_qs(urlparse.urlparse(location).query)['code'][0]
        self.assertTrue(Grant.objects.filter(code=code).exists())

        # use the code/grant
        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code})
        self.assertEquals(200, response.status_code)
        token = json.loads(response.content)
        self.assertTrue('access_token' in token)
        access_token = token['access_token']
        self.assertTrue('refresh_token' in token)
        refresh_token = token['refresh_token']

        # make sure the grant is gone
        self.assertFalse(Grant.objects.filter(code=code).exists())
        # and verify that the AccessToken and RefreshToken exist
        self.assertTrue(AccessToken.objects.filter(token=access_token).exists())
        self.assertTrue(RefreshToken.objects.filter(token=refresh_token).exists())

        # refresh the token
        response = self.client.post(self.access_token_url(), {
            'grant_type': 'refresh_token',
            'refresh_token': token['refresh_token'],
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
        })
        self.assertEqual(200, response.status_code)
        token = json.loads(response.content)
        self.assertTrue('access_token' in token)
        self.assertNotEquals(access_token, token['access_token'])
        self.assertTrue('refresh_token' in token)
        self.assertNotEquals(refresh_token, token['refresh_token'])

        # make sure the orig AccessToken and RefreshToken are gone
        self.assertFalse(AccessToken.objects.filter(token=access_token).exists())
        self.assertFalse(RefreshToken.objects.filter(token=refresh_token).exists())


class AccessTokenDetailViewTests(TestCase):
    JSON_CONTENT_TYPE = 'application/json'

    def setUp(self):
        super(AccessTokenDetailViewTests, self)
        self.user = User.objects.create_user('TEST-USER', 'user@example.com')
        self.oauth_client = Client.objects.create(client_type=constants.CONFIDENTIAL)

    def assert_invalid_token_response(self, token):
        """ Verifies that the view returns an invalid token response for the specified token. """
        url = reverse('oauth2:access_token_detail', kwargs={'token': token})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)

        self.assertEqual(response['Content-Type'], self.JSON_CONTENT_TYPE)
        self.assertEqual(response.content, json.dumps({'error': 'invalid_token'}))

    def test_invalid_token(self):
        """
        If the requested token is invalid for any reason (expired, doesn't exist, etc.) the view should return HTTP 400.
        """
        # Non-existent token
        self.assert_invalid_token_response('abc')

        # Expired token
        access_token = AccessToken.objects.create(user=self.user, client=self.oauth_client,
                                                  expires=datetime.datetime.min)
        self.assert_invalid_token_response(access_token.token)

    def test_valid_token(self):
        """ If the token is valid, details about the token should be returned. """

        expires = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        access_token = AccessToken.objects.create(user=self.user, client=self.oauth_client, scope=constants.READ,
                                                  expires=expires)

        url = reverse('oauth2:access_token_detail', kwargs={'token': access_token.token})

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], self.JSON_CONTENT_TYPE)

        expected = {
            'username': self.user.username,
            'scope': 'read',
            'expires': expires.isoformat()
        }
        self.assertEqual(response.content, json.dumps(expected))
