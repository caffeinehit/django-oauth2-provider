from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from provider.oauth2.models import Client, Grant
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
