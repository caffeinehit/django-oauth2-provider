import base64
import json
import datetime
from urllib.parse import urlparse, parse_qs, quote

from unittest.mock import patch
from django.http import QueryDict
from django.conf import settings
from django.shortcuts import reverse
from django.utils.html import escape
from django.test import TestCase
from django.contrib.auth.models import User
from provider import constants, scope
from provider.compat import skipIfCustomUser
from provider.templatetags.scope import scopes
from provider.utils import now as date_now
from provider.oauth2.forms import ClientForm
from provider.oauth2.models import Client, Grant, AccessToken, RefreshToken, AuthorizedClient, AwsAccount
from provider.oauth2.backends import BasicClientBackend, RequestParamsClientBackend
from provider.oauth2.backends import AccessTokenBackend


@skipIfCustomUser
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

    def get_public_client(self):
        return Client.objects.get(id=3)

    def get_pkce_client(self):
        return Client.objects.get(id=4)

    def get_pkce_plain_client(self):
        return Client.objects.get(id=5)

    def get_grant(self):
        return Grant.objects.all()[0]

    def get_user(self):
        return User.objects.get(id=1)

    def get_password(self):
        return 'test'

    def get_aws_role(self):
        return AwsAccount.objects.get(id=1)

    def _login_and_authorize(self, url_func=None):
        if url_func is None:
            def url_func():
                return self.auth_url() + '?client_id={}&response_type=code&state=abc'.format(
                    self.get_client().client_id
                )

        response = self.client.get(url_func())
        response = self.client.get(self.auth_url2())

        response = self.client.post(self.auth_url2(), {'authorize': True, 'scope': 'read'})
        self.assertEqual(302, response.status_code, response.content)
        self.assertIn(self.redirect_url(), response['Location'])


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
        self.assertEqual('/login/', urlparse(response['Location']).path)

        self.login()

        response = self.client.get(self.auth_url())

        self.assertEqual(302, response.status_code)

        self.assertTrue(self.auth_url2() in response['Location'])

    def test_authorization_requires_client_id(self):
        self.login()
        response = self.client.get(self.auth_url())
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertIn("An unauthorized client tried to access your resources.", response.content.decode('utf8'))

    def test_authorization_rejects_invalid_client_id(self):
        self.login()
        response = self.client.get(self.auth_url() + '?client_id=123')
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertIn(b"An unauthorized client tried to access your resources.", response.content)

    def test_authorization_requires_response_type(self):
        self.login()
        response = self.client.get(self.auth_url() + '?client_id=%s' % self.get_client().client_id)
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertIn(escape(u"No 'response_type' supplied."), response.content.decode('utf8'))

    def test_authorization_requires_supported_response_type(self):
        self.login()
        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=unsupported' % self.get_client().client_id)
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertIn(escape(u"'unsupported' is not a supported response type."), response.content.decode('utf8'))

        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=code' % self.get_client().client_id)
        response = self.client.get(self.auth_url2())
        self.assertEqual(200, response.status_code, response.content)

        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=token' % self.get_client().client_id)
        response = self.client.get(self.auth_url2())
        self.assertEqual(200, response.status_code)

    def test_authorization_requires_a_valid_redirect_uri(self):
        self.login()

        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=code&redirect_uri=%s' % (
            self.get_client().client_id,
            self.get_client().redirect_uri + '-invalid'))
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertIn(escape("The requested redirect didn't match the client settings."), response.content.decode('utf8'))

        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=code&redirect_uri=%s' % (
            self.get_client().client_id,
            self.get_client().redirect_uri))
        response = self.client.get(self.auth_url2())

        self.assertEqual(200, response.status_code)

    def test_authorization_requires_a_valid_scope(self):
        self.login()

        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=code&scope=invalid+invalid2' % self.get_client().client_id)

        self.assertEqual(400, response.status_code)
        self.assertIn(escape(u"Invalid scope."), response.content.decode('utf8'))

        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=code&scope=%s' % (
            self.get_client().client_id,
            constants.SCOPES[0][1]))
        response = self.client.get(self.auth_url2())
        self.assertEqual(200, response.status_code)

    def test_authorization_is_not_granted(self):
        self.login()

        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=code' % self.get_client().client_id)
        response = self.client.get(self.auth_url2())

        response = self.client.post(self.auth_url2(), {'authorize': False, 'scope': constants.SCOPES[0][1]})
        self.assertEqual(302, response.status_code, response.content)
        self.assertTrue(self.redirect_url() in response['Location'])

        response = self.client.get(self.redirect_url())

        self.assertEqual(302, response.status_code)
        self.assertTrue('error=access_denied' in response['Location'])
        self.assertFalse('code' in response['Location'])

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

    def test_pkce_authorization_is_granted(self):
        code_verifier = '8d6e7d6d3375bc536fb276ca1e3feebba6f29dd4'
        code_challenge = 'cvbVJuj0KkRIpHMCkBOsZojlbqMhu-H7jkXx9U6E_3Y='

        self.login()
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state=abc&code_challenge={}&code_challenge_method=S256'.format(
                self.get_pkce_client().client_id, code_challenge,
            )

        self._login_and_authorize(url_func)

        response = self.client.get(self.redirect_url())
        self.assertEqual(302, response.status_code)
        self.assertFalse('error' in response['Location'])
        self.assertTrue('code' in response['Location'])

    def test_pkce_authorization_plain_prohibited(self):
        code_verifier = '8d6e7d6d3375bc536fb276ca1e3feebba6f29dd4'
        code_challenge = 'cvbVJuj0KkRIpHMCkBOsZojlbqMhu-H7jkXx9U6E_3Y='

        self.login()
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state=abc&code_challenge={}'.format(
                self.get_pkce_client().client_id, code_verifier,
            )

        response = self.client.get(url_func())
        response = self.client.get(self.auth_url2())
        response = self.client.post(self.auth_url2(), {'authorize': True, 'scope': 'read'})

        self.assertEqual(400, response.status_code)
        self.assertIn('client does not allow code_challenge_method=plain', response.content.decode())

    def test_pkce_plain_authorization_is_granted(self):
        code_verifier = '8d6e7d6d3375bc536fb276ca1e3feebba6f29dd4'
        code_challenge = 'cvbVJuj0KkRIpHMCkBOsZojlbqMhu-H7jkXx9U6E_3Y='

        self.login()
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state=abc&code_challenge={}'.format(
                self.get_pkce_plain_client().client_id, code_verifier,
            )

        self._login_and_authorize(url_func)

        response = self.client.get(self.redirect_url())
        self.assertEqual(302, response.status_code)
        self.assertFalse('error' in response['Location'])
        self.assertTrue('code' in response['Location'])

    # # FIXME: Not sure what the error condition is that should exist here.
    # def test_redirect_requires_valid_data(self):
    #     self.login()
    #     response = self.client.get(self.redirect_url())
    #     self.assertEqual(400, response.status_code)


class AccessTokenTest(BaseOAuth2TestCase):
    fixtures = ['test_oauth2.json']

    def test_access_token_get_expire_delta_value(self):
        user = self.get_user()
        client = self.get_client()
        token = AccessToken.objects.create(user=user, client=client)
        now = date_now()
        default_expiration_timedelta = constants.EXPIRE_DELTA
        current_expiration_timedelta = datetime.timedelta(seconds=token.get_expire_delta(reference=now))
        self.assertTrue(abs(current_expiration_timedelta - default_expiration_timedelta) <= datetime.timedelta(seconds=1))

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
        # self.assertEqual('invalid_grant', json.loads(response.content)['error'])

    def test_authorize_once(self):
        state = 'abc'
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state={}'.format(
                self.get_client().client_id,
                state,
            )

        self.login()
        self._login_and_authorize(url_func)
        authorized_client = AuthorizedClient.objects.get()

        state = 'def'
        response = self.client.get(url_func())
        self.assertEqual(response.url, "/oauth2/authorize/confirm")

        confirm_response = self.client.get(response.url)
        self.assertEqual(confirm_response.status_code, 302)

    def test_authorize_every_time(self):
        state = 'abc'
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state={}'.format(
                self.get_public_client().client_id,
                state,
            )

        self.login()
        self._login_and_authorize(url_func)

        state = 'def'
        response = self.client.get(url_func())
        self.assertEqual(response.url, "/oauth2/authorize/confirm")

    def test_authorize_additional_scope(self):
        state = 'abc'
        scopes = 'basic'
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state={}&scope={}'.format(
                self.get_public_client().client_id,
                state,
                quote(scopes),
            )

        self.login()
        self._login_and_authorize(url_func)

        state = 'def'
        scopes = 'basic advanced'
        response = self.client.get(url_func())
        self.assertEqual(response.url, "/oauth2/authorize/confirm")

    def _login_authorize_get_token(self):
        required_props = ['access_token', 'token_type']

        self.login()
        self._login_and_authorize()

        response = self.client.get(self.redirect_url())
        query = QueryDict(urlparse(response['Location']).query)
        code = query['code']

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code})

        self.assertEqual(200, response.status_code, response.content)

        token = json.loads(response.content)

        for prop in required_props:
            self.assertIn(prop, token, "Access token response missing "
                    "required property: %s" % prop)

        return token

    def test_fetching_access_token_with_valid_grant(self):
        self._login_authorize_get_token()

    def test_fetching_access_token_with_invalid_grant_type(self):
        self.login()
        self._login_and_authorize()
        response = self.client.get(self.redirect_url())

        query = QueryDict(urlparse(response['Location']).query)
        code = query['code']

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'invalid_grant_type',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code
        })

        self.assertEqual(400, response.status_code)
        self.assertEqual('unsupported_grant_type', json.loads(response.content)['error'],
            response.content)

    def test_fetching_access_token_multiple_times(self):
        self._login_authorize_get_token()
        code = self.get_grant().code

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code})

        self.assertEqual(400, response.status_code)
        # self.assertEqual('invalid_grant', json.loads(response.content)['error'])

    def test_access_token_native_client(self):
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state=abc'.format(
                self.get_public_client().client_id
            )

        self.login()
        self._login_and_authorize(url_func)

        self.assertEqual(self.get_public_client().client_type, constants.PUBLIC)

        response = self.client.get(self.redirect_url())
        query = QueryDict(urlparse(response['Location']).query)
        code = query['code']

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_public_client().client_id,
            'code': code})

        self.assertEqual(200, response.status_code, response.content)

        token_response = json.loads(response.content)

        self.assertNotIn('refresh_token', token_response)

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
        self.assertEqual('invalid_grant', json.loads(response.content)['error'])

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
        self.assertEqual('invalid_grant', json.loads(response.content)['error'],
            response.content)

    def test_password_grant_public(self):
        c = self.get_client()
        c.client_type = constants.PUBLIC
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
        c.client_type = constants.CONFIDENTIAL
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
        c.client_type = constants.PUBLIC
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
        c.client_type = constants.CONFIDENTIAL
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

    @patch('urllib.request.urlopen')
    def test_aws_grant_invalid_caller_identity(self, urlopen):
        headers = {
            "header1": "a",
            "header2": "b",
        }
        post_body = "mypostbody"

        caller_identity_result = """
        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <GetCallerIdentityResult>
                <Arn>arn:aws:iam::123456789012:user/myuser</Arn>
                <UserId>AIDA27</UserId>
                <Account>123456789012</Account>
            </GetCallerIdentityResult>
            <ResponseMetadata>
                <RequestId>00000000-3558-43b5-8157-07d0769322b5</RequestId>
            </ResponseMetadata>
        </GetCallerIdentityResponse>""".strip("\n ").encode('utf-8')

        urlopen.return_value.read.return_value = caller_identity_result

        urlopen.return_value.code = 200

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'aws_identity',
            'region': "us-west-2",
            'post_body': post_body,
            'headers_json': json.dumps(headers),
        })

        self.assertEqual(400, response.status_code)
        self.assertEqual('not_authorized', json.loads(response.content),
                         response.content)

    @patch('urllib.request.urlopen')
    def test_aws_grant_valid_caller_identity(self, urlopen):
        headers = {
            "header1": "a",
            "header2": "b",
        }
        post_body = "mypostbody"

        caller_identity_result = """
        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <GetCallerIdentityResult>
                <Arn>arn:aws:iam::123456789012:assumed-role/testrole/testsession</Arn>
                <UserId>AIDA27</UserId>
                <Account>123456789012</Account>
            </GetCallerIdentityResult>
            <ResponseMetadata>
                <RequestId>00000000-3558-43b5-8157-07d0769322b5</RequestId>
            </ResponseMetadata>
        </GetCallerIdentityResponse>""".strip("\n ").encode('utf-8')

        urlopen.return_value.read.return_value = caller_identity_result

        urlopen.return_value.code = 200

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'aws_identity',
            'region': "us-west-2",
            'post_body': post_body,
            'headers_json': json.dumps(headers),
        })

        self.assertEqual(200, response.status_code)
        self.assertNotIn('refresh_token', json.loads(response.content))

    def test_access_token_pkce_client(self):
        required_props = ['access_token', 'token_type', 'refresh_token']

        code_verifier = '8d6e7d6d3375bc536fb276ca1e3feebba6f29dd4'
        code_challenge = 'cvbVJuj0KkRIpHMCkBOsZojlbqMhu-H7jkXx9U6E_3Y='

        self.login()
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state=abc&code_challenge={}&code_challenge_method=S256'.format(
                self.get_pkce_client().client_id, code_challenge,
            )

        self._login_and_authorize(url_func=url_func)

        response = self.client.get(self.redirect_url())
        query = QueryDict(urlparse(response['Location']).query)
        code = query['code']

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_pkce_client().client_id,
            'code_verifier': code_verifier,
            'code': code})

        self.assertEqual(200, response.status_code, response.content)

        token = json.loads(response.content)

        for prop in required_props:
            self.assertIn(prop, token, "Access token response missing "
                    "required property: %s" % prop)

        return token

    def test_access_token_pkce_plain_client(self):
        required_props = ['access_token', 'token_type']

        code_verifier = '8d6e7d6d3375bc536fb276ca1e3feebba6f29dd4'
        code_challenge = 'cvbVJuj0KkRIpHMCkBOsZojlbqMhu-H7jkXx9U6E_3Y='

        self.login()
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state=abc&code_challenge={}'.format(
                self.get_pkce_plain_client().client_id, code_verifier,
            )

        self._login_and_authorize(url_func=url_func)

        response = self.client.get(self.redirect_url())
        query = QueryDict(urlparse(response['Location']).query)
        code = query['code']

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_pkce_plain_client().client_id,
            'code_verifier': code_verifier,
            'code': code})

        self.assertEqual(200, response.status_code, response.content)

        token = json.loads(response.content)

        for prop in required_props:
            self.assertIn(prop, token, "Access token response missing "
                    "required property: %s" % prop)

        return token

    def test_access_token_pkce_plain_client_with_S256(self):
        required_props = ['access_token', 'token_type']

        code_verifier = '8d6e7d6d3375bc536fb276ca1e3feebba6f29dd4'
        code_challenge = 'cvbVJuj0KkRIpHMCkBOsZojlbqMhu-H7jkXx9U6E_3Y='

        self.login()
        def url_func():
            return self.auth_url() + '?client_id={}&response_type=code&state=abc&code_challenge={}&code_challenge_method=S256'.format(
                self.get_pkce_plain_client().client_id, code_challenge,
            )

        self._login_and_authorize(url_func=url_func)

        response = self.client.get(self.redirect_url())
        query = QueryDict(urlparse(response['Location']).query)
        code = query['code']

        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_pkce_plain_client().client_id,
            'code_verifier': code_verifier,
            'code': code})

        self.assertEqual(200, response.status_code, response.content)

        token = json.loads(response.content)

        for prop in required_props:
            self.assertIn(prop, token, "Access token response missing "
                    "required property: %s" % prop)

        return token


class AuthBackendTest(BaseOAuth2TestCase):
    fixtures = ['test_oauth2']

    def test_basic_client_backend(self):
        request = type('Request', (object,), {'META': {}})()
        user_pass = "{0}:{1}".format(
            self.get_client().client_id,
            self.get_client().client_secret
        )
        user_pass64 = base64.b64encode(user_pass.encode('utf8')).decode('utf8')
        request.META['HTTP_AUTHORIZATION'] = "Basic {}".format(user_pass64)

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
        authenticated = backend.authenticate(access_token=token.token,
                client=client)

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
        self.assertIn("A secure connection is required.", response.content.decode('utf8'))

    def test_access_token_enforces_SSL(self):
        response = self.client.post(self.access_token_url(), {})

        self.assertEqual(400, response.status_code)
        self.assertIn("A secure connection is required.", response.content.decode('utf8'))


class ClientFormTest(TestCase):
    def test_client_form(self):
        form = ClientForm({'name': 'TestName', 'url': 'http://127.0.0.1:8000',
            'redirect_uri': 'http://localhost:8000/'})

        self.assertFalse(form.is_valid())

        form = ClientForm({
            'name': 'TestName',
            'url': 'http://127.0.0.1:8000',
            'redirect_uri': 'http://localhost:8000/',
            'client_type': constants.CONFIDENTIAL})
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
        self.assertNotIn('error', location)
        self.assertIn('code', location)
        print(location)
        # verify that Grant with code exists
        parsed_location = urlparse(location)
        code = parse_qs(parsed_location.query)['code'][0]
        self.assertTrue(Grant.objects.filter(code=code).exists())

        # use the code/grant
        response = self.client.post(self.access_token_url(), {
            'grant_type': 'authorization_code',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'code': code})
        self.assertEqual(200, response.status_code)
        token = json.loads(response.content)
        self.assertTrue('access_token' in token)
        access_token = token['access_token']
        self.assertTrue('refresh_token' in token)
        refresh_token = token['refresh_token']

        # make sure the grant is gone
        self.assertFalse(Grant.objects.filter(code=code).exists())
        # and verify that the AccessToken and RefreshToken exist
        self.assertTrue(AccessToken.objects.filter(token=access_token)
                        .exists())
        self.assertTrue(RefreshToken.objects.filter(token=refresh_token)
                        .exists())

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
        self.assertNotEqual(access_token, token['access_token'])
        self.assertTrue('refresh_token' in token)
        self.assertNotEqual(refresh_token, token['refresh_token'])

        # make sure the orig AccessToken and RefreshToken are gone
        self.assertFalse(AccessToken.objects.filter(token=access_token)
                         .exists())
        self.assertFalse(RefreshToken.objects.filter(token=refresh_token)
                         .exists())
