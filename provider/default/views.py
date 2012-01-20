# Create your views here.
from django.core.urlresolvers import reverse
from provider.default.forms import AuthorizationRequestForm
from provider.default.models import Client
from provider.views import Capture, Authorize, Redirect, AccessToken

class Mixin(object):
    pass

class Capture(Capture, Mixin):
    def get_redirect_url(self, request):
        return reverse('oauth2:authorize')
    
class Authorize(Authorize, Mixin):
    def get_request_form(self, client, data):
        return AuthorizationRequestForm(data, client = client)
    
    def get_authorization_form(self, request, client, data, client_data):
        return None
    
    def get_client(self, client_id):
        try:
            return Client.objects.get(client_id = client_id)
        except Client.DoesNotExist:
            return None

    def save_authorization(self, request, client, form, client_data):
        auth = form.save(commit = False)
        auth.user = request.user
        auth.client = client
        auth.save()
        return auth


class Redirect(Redirect, Mixin):
    pass

class AccessToken(AccessToken, Mixin):
    pass

