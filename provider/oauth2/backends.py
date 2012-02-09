from datetime import datetime
from provider.oauth2.forms import ClientAuthForm
from provider.oauth2.models import Client, AccessToken

class BaseBackend(object):
    """
    Base backend used to authenticate clients as defined in :draft:`1` against
    our database.
    """
    def authenticate(self, request=None):
        """
        Override this method to implement your own authentication backend.
        Return a client or ``None`` in case of failure.
        """

class BasicClientBackend(object):
    """
    Backend that tries to authenticate a client through HTTP authorization headers
    as defined in :draft:`2.3.1`.
    """
    def authenticate(self, request=None):
        auth = request.META.get('HTTP_AUTHORIZATION')

        if auth is None or auth == '':
            return None
        
        try:
            basic, base64 = auth.split(' ')
            client_id, client_secret = base64.decode('base64').split(':')
            
            form = ClientAuthForm({'client_id': client_id, 'client_secret': client_secret})
            
            if form.is_valid():
                return form.cleaned_data.get('client')
            return None

        except ValueError, e:
            # Auth header was malformed, unpacking went wrong
            return None


class RequestParamsClientBackend(object):
    """
    Backend that tries to authenticate a client through request parameters
    which might be in the request body or URI as defined in :draft:`2.3.1`.
    """
    def authenticate(self, request=None):
        if request is None:
            return None
        
        form = ClientAuthForm(request.REQUEST)
        
        if form.is_valid():
            return form.cleaned_data.get('client')
        
        return None
        
        
class AccessTokenBackend(object):
    """ 
    Authenticate a user via access token and client object.
    """
    
    def authenticate(self, access_token=None, client=None):
        try:
            return AccessToken.objects.get(access_token=access_token,
                expiry__gt=datetime.now(), client=client)
        except AccessToken.DoesNotExist:
            return None

