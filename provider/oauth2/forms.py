from datetime import datetime
from django import forms
from django.utils.translation import ugettext_lazy as _
from provider import constants
from provider.constants import CONFIDENTIAL, ENFORCE_CLIENT_SECURE, SCOPES, \
    RESPONSE_TYPE_CHOICES
from provider.forms import OAuthValidationError, OAuthForm
from provider.oauth2.models import Client, Grant, RefreshToken
from provider.utils import get_client, get_redirect_uri
import urlparse

class ClientAuthForm(forms.Form):
    client_id = forms.CharField()
    client_secret = forms.CharField()
    
    def clean(self):
        data = self.cleaned_data
        try:
            client = Client.objects.get(client_id=data.get('client_id'),
                client_secret=data.get('client_secret'))
        except Client.DoesNotExist:
            raise forms.ValidationError(_("Client could not be validated with key pair."))

        data['client'] = client
        return data

class ClientForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = ('url', 'client_type', 'redirect_uri',)
        
    def clean(self):
        data = self.cleaned_data

        confidential = data['client_type'] == CONFIDENTIAL        
        https = urlparse.urlparse(data['redirect_uri']).scheme == 'https'
        
        if ENFORCE_CLIENT_SECURE and not https:
            raise forms.ValidationError(_("Your callback URL must be secure."))

        return data
    
class AuthorizationRequestForm(OAuthForm):
    """
    This form is used to validate the request data that the authorization 
    endpoint receives from clients.
    
    The data per :rfc 4.1.1: includes:
    
    :param response_type: "code" or "token", depending on the grant type.
    :param redirect_uri: Where the client would like to redirect the user
        back to. This has to match whatever value was saved while creating
        the client.
    :param scope: The scope that the authorization should include.
    :param state: Opaque - just pass back to client for validation.
    """
    # Setting all required fields to falls to explicitly check by hand
    # and use custom error messages that can be reused in the OAuth2
    # protocol
    response_type = forms.CharField(required=False)
    redirect_uri = forms.URLField(required=False)
    scope = forms.CharField(required=False)
    state = forms.CharField(required=False)
    
    def clean_response_type(self):
        """
        :rfc 3.1.1: Lists of values are space delimited.
        """
        response_type = self.cleaned_data.get('response_type')
        
        if not response_type:
            raise OAuthValidationError({'error': 'invalid_request',
                'error_description': "No 'response_type' supplied."})

        types = response_type.split(" ")
        
        for type in types:
            if type not in RESPONSE_TYPE_CHOICES:
                raise OAuthValidationError({'error': 'unsupported_response_type',
                    'error_description': u"'%s' is not a supported response type." % type})
        
        return response_type

    def clean_redirect_uri(self):
        """
        :rfc 3.1.2: The redirect value has to match what was saved on the 
            authorization server.
        """
        redirect_uri = self.cleaned_data.get('redirect_uri')

        if redirect_uri:
            if not redirect_uri == self.client.redirect_uri:
                raise OAuthValidationError({'error': 'invalid_request',
                    'error_description': _("The requested redirect didn't match the client settings.")})
        
        return redirect_uri        
        
    def clean_scope(self):
        """
        :rfc 3.3: The scope of access requested by the client. This has to match
            what scopes are available. A user can accept, reject or grant a 
            different scope.
        """
        scope = self.cleaned_data.get('scope')

        if not scope:
            return ''
        
        scope = scope.split(' ')
        
        for s in scope:
            if s not in SCOPES:
                raise OAuthValidationError({'error': 'invalid_scope',
                    'error_description': _("'%s' is not a valid scope." % s)})
    
        return u' '.join(scope)
    
class AuthorizationForm(forms.Form):
    """
    A form used to ask the resource owner for authorization of a given client.
    """
    authorize = forms.BooleanField(required=False)
    scope = forms.MultipleChoiceField(choices=[(c, c) for c in constants.SCOPES],
        required=True)

    def clean_scope(self):
        scope = self.cleaned_data.get('scope')
        
        return ' '.join(scope)
    
    def save(self, **kwargs):
        authorize = self.cleaned_data.get('authorize')

        if not authorize:
            return None
        
        grant = Grant()
        return grant

class RefreshTokenForm(OAuthForm):
    """
    Check and return a refresh token
    """
    refresh_token = forms.CharField()
    
    def clean_refresh_token(self):
        token = self.cleaned_data.get('refresh_token')
        
        try:
            token = RefreshToken.objects.get(token=token,
                expired=False, client=self.client)
        except RefreshToken.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})
        
        return token
    
class GrantForm(OAuthForm):
    """
    Check and return a grant
    """
    code = forms.CharField()

    def clean_code(self):
        code = self.cleaned_data.get('code')
        try:
            self.cleaned_data['grant'] = Grant.objects.get(
                code=code, client=self.client, expires__gt=datetime.now())
        except Grant.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})
        return code
