import json
from urllib.parse import urlparse

from django.shortcuts import reverse
from django.http import QueryDict

from provider.oauth2.models import Scope
from provider.oauth2.mixins import OAuthRegisteredScopes
from provider.oauth2.tests.test_views import BaseOAuth2TestCase


class MiddlewareTestCase(BaseOAuth2TestCase):
    fixtures = ['test_oauth2.json']

    def setUp(self):
        if not Scope.objects.filter(name='read').exists():
            Scope.objects.create(name='read')

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

    def test_mixin_scopes(self):
        self.assertIn('read', OAuthRegisteredScopes.scopes)

    def test_no_token(self):
        # user_url = self.live_server_url + reverse('tests:user', args=[self.get_user().pk])
        # result = requests.get(user_url)

        user_url = reverse('tests:user', args=[self.get_user().pk])
        result = self.client.get(user_url)

        self.assertEqual(result.status_code, 401)

    def test_token_access(self):
        self.login()
        token_info = self._login_authorize_get_token()
        token = token_info['access_token']

        # Create a new client to ensure a clean session
        oauth_client = self.client_class()

        user_url = reverse('tests:user', args=[self.get_user().pk])
        result = oauth_client.get(user_url, {'access_token': token})

        self.assertEqual(result.status_code, 200)
        result_json = result.json()
        self.assertEqual(result_json.get('id'), self.get_user().pk)

    def test_unauthorized_scope(self):
        self.login()
        token_info = self._login_authorize_get_token()
        token = token_info['access_token']

        badscope_url = reverse('tests:badscope')

        oauth_client = self.client_class()

        result = oauth_client.get(badscope_url, {'access_token': token})

        self.assertEqual(result.status_code, 401)
        result_json = result.json()
        # self.assertEqual(result_json.get('id'), self.get_user().pk)

    def test_no_stored_session(self):
        self.login()
        token_info = self._login_authorize_get_token()
        token = token_info['access_token']

        oauth_client = self.client_class()

        user_url = reverse('tests:user', args=[self.get_user().pk])
        result = oauth_client.get(user_url, {'access_token': token})

        self.assertNotIn('sessionid', result.cookies)
