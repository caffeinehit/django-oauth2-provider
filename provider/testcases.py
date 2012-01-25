from django.conf import settings
from django.http import QueryDict
from django.test import TestCase
from django.utils.html import escape
from provider import constants
import json
import urlparse

class TestMixin(object):
    
    def _login_and_authorize(self, url_func=None):
        if url_func is None:
            url_func = lambda: self.auth_url() + '?client_id=%s&response_type=code&state=abc' % self.get_client().client_id
        
        response = self.client.get(url_func())
        response = self.client.get(self.auth_url2())
        
        response = self.client.post(self.auth_url2(), {'authorize': True, 'scope': constants.SCOPES[0][1]})
        self.assertEqual(302, response.status_code, response.content)
        self.assertTrue(self.redirect_url() in response['Location'])
        
    
class AuthorizationTest(TestCase, TestMixin):
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
        
    def test_authorization_requires_client_id(self):
        self.login()
        response = self.client.get(self.auth_url())
        response = self.client.get(self.auth_url2())
        
        self.assertEqual(400, response.status_code)
        self.assertTrue("An unauthorized client tried to access your resources." in response.content)

    def test_authorization_rejects_invalid_client_id(self):
        self.login()
        response = self.client.get(self.auth_url() + '?client_id=123')
        response = self.client.get(self.auth_url2())
        
        self.assertEqual(400, response.status_code)
        self.assertTrue("An unauthorized client tried to access your resources." in response.content)

    def test_authorization_requires_response_type(self):
        self.login()
        response = self.client.get(self.auth_url() + '?client_id=%s' % self.get_client().client_id)
        response = self.client.get(self.auth_url2())
        
        self.assertEqual(400, response.status_code)
        self.assertTrue(escape(u"No 'response_type' supplied.") in response.content)
        
    def test_authorization_requires_supported_response_type(self):
        self.login()
        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=unsupported' % self.get_client().client_id)
        response = self.client.get(self.auth_url2())

        self.assertEqual(400, response.status_code)
        self.assertTrue(escape(u"'unsupported' is not a supported response type.") in response.content)

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
        self.assertTrue(escape(u"The requested redirect didn't match the client settings.") in response.content)
        
        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=code&redirect_uri=%s' % (
            self.get_client().client_id,
            self.get_client().redirect_uri))
        response = self.client.get(self.auth_url2())
        
        self.assertEqual(200, response.status_code)
        
    def test_authorization_requires_a_valid_scope(self):
        self.login()
        
        response = self.client.get(self.auth_url() + '?client_id=%s&response_type=code&scope=invalid+invalid2' % self.get_client().client_id)
        response = self.client.get(self.auth_url2())
        
        self.assertEqual(400, response.status_code)
        self.assertTrue(escape(u"'invalid' is not a valid scope.") in response.content)
        
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

class AccessTokenTest(TestCase, TestMixin):
    fixtures = ['test_oauth2']
    
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
        
        return json.loads(response.content)
    
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
        self.assertEqual('invalid_grant', json.loads(response.content)['error'],
            response.content)
    
    def test_password_grant(self):
        response = self.client.post(self.access_token_url(), {
            'grant_type': 'password',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'username': self.get_user().username,
            'password': self.get_password(),
        })
        
        self.assertEqual(200, response.status_code, response.content)
        
        response = self.client.post(self.access_token_url(), {
            'grant_type': 'password',
            'client_id': self.get_client().client_id,
            'client_secret': self.get_client().client_secret,
            'username': self.get_user().username,
            'password': self.get_password() + 'invalid',
        })
        
        self.assertEqual(400, response.status_code, response.content)
        self.assertEqual('invalid_grant', json.loads(response.content)['error'])
        

class EnforceSecureTest(TestCase):
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
        
