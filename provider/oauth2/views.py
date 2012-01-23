# Create your views here.
from django.core.urlresolvers import reverse
from provider.oauth2.auth import BasicClientBackend, RequestParamsClientBackend
from provider.oauth2.forms import AuthorizationRequestForm, AuthorizationForm, \
    GrantForm
from provider.oauth2.models import Client
from provider.views import Capture, Authorize, Redirect, AccessToken

class Mixin(object):
    pass

class Capture(Capture, Mixin):
    def get_redirect_url(self, request):
        return reverse('oauth2:authorize-2')
    
class Authorize(Authorize, Mixin):
    def get_request_form(self, client, data):
        return AuthorizationRequestForm(data, client = client)
    
    def get_authorization_form(self, request, client, data, client_data):
        return AuthorizationForm(data)
    
    def get_client(self, client_id):
        try:
            return Client.objects.get(client_id = client_id)
        except Client.DoesNotExist:
            return None

    def get_redirect_url(self, request):
        return reverse('oauth2:redirect')

    def save_authorization(self, request, client, form, client_data):
        auth = form.save(commit = False)

        if auth is None:
            return None

        auth.user = request.user
        auth.client = client
        auth.redirect_uri = client_data.get('redirect_uri', '')
        auth.save()
        return auth.code


class Redirect(Redirect, Mixin):
    pass

class AccessToken(AccessToken, Mixin):
    authentication = (
        BasicClientBackend,
        RequestParamsClientBackend,
    )
    
    def get_grant(self, request, data, client):
        form = GrantForm(data, client = client)
        
        if form.is_valid():
            return True, form.cleaned_data.get('grant')
        return False, form.errors
        

