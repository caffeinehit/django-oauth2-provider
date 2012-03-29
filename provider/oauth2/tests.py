from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.test import TestCase
from provider import constants, scope
from provider.oauth2.forms import ClientForm
from provider.oauth2.models import Client, Grant
from provider.templatetags.scope import scopes
from provider.testcases import AuthorizationTest, AccessTokenTest, \
    EnforceSecureTest


class Mixin(object):
    def login(self):
        self.client.login(username='test-user-1', password='test')
    def auth_url(self):
        return reverse('oauth2:authorize')
    def auth_url2(self):
        return reverse('oauth2:authorize-2')
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
        
class AuthorizationTest(AuthorizationTest, Mixin):
    pass

class AccessTokenTest(AccessTokenTest, Mixin):
    pass

class EnforceSecureTest(EnforceSecureTest, Mixin):
    pass

class TestClientForm(TestCase, Mixin):
    def test_client_form(self):
        form = ClientForm({'name': 'TestName', 'url': 'http://127.0.0.1:8000',
            'redirect_uri': 'http://localhost:8000/'})
        
        self.assertFalse(form.is_valid())
        
        form = ClientForm({'name': 'TestName', 'url': 'http://127.0.0.1:8000',
            'redirect_uri': 'http://localhost:8000/', 'client_type': constants.CLIENT_TYPES[0][0]})
        self.assertTrue(form.is_valid())
        client = form.save()
        
class TestScope(TestCase, Mixin):
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
        
        self.assertEqual('read write', ' '.join(names))
    
    def test_get_scope_ints(self):
        self.assertEqual(constants.READ, scope.to_int('read'))
        self.assertEqual(constants.READ_WRITE, scope.to_int('write'))
        self.assertEqual(constants.READ_WRITE, scope.to_int('read', 'write'))
        self.assertEqual(0, scope.to_int('invalid'))
        self.assertEqual(1, scope.to_int('invalid', default=1))


    def test_template_filter(self):
        names = scopes(constants.READ)
        self.assertEqual('read', ' '.join(names))
        
        names = scope.names(constants.READ_WRITE)
        names.sort()
        
        self.assertEqual('read write', ' '.join(names))
