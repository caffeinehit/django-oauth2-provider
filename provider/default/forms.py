from django import forms
from django.utils.translation import ugettext_lazy as _
from provider.constants import CONFIDENTIAL, ENFORCE_CLIENT_SECURE, \
     SCOPES, RESPONSE_TYPE_CHOICES
from provider.default.models import Client
from provider.utils import get_client, get_redirect_uri
import urlparse

class ClientAuthForm(forms.Form):
    client_id = forms.CharField()
    client_secret = forms.CharField()
    
    def clean(self):
        data = self.cleaned_data
        try:
            client = Client.objects.get(client_id = data.get('client_id'),
                client_secret = data.get('client_secret'))
        except Client.DoesNotExist:
            raise forms.ValidationError(_("Client could not be validated with key pair."))

        data['client'] = client
        return data

class ClientForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = ('url', 'client_type', 'callback_url', )
        
    def clean(self):
        data = self.cleaned_data

        confidential = data['client_type'] == CONFIDENTIAL        
        https = urlparse.urlparse(data['callback_url']).scheme == 'https'
        
        if ENFORCE_CLIENT_SECURE and not https:
            raise forms.ValidationError(_("Your callback URL must be secure."))

        return data
    
class AuthorizationRequestForm(forms.ModelForm):
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
    response_type = forms.CharField()
    redirect_uri = forms.URLField(required = False)
    scope = forms.CharField(required = False)
    state = forms.CharField(required = False)
    
    def __init__(self, *args, **kwargs):
        """
        :param client: **required** The currently authenticated client.
        """
        self.client = kwargs.pop('client')
        super(AuthorizationRequestForm, self).__init__(*args, **kwargs)
    
    def clean_response_type(self):
        """
        :rfc 3.1.1: Lists of values are space delimited.
        """
        response_type = self.cleaned_data.get('response_type')
        types = response_type.split(" ")
        
        for type in types:
            if type not in RESPONSE_TYPE_CHOICES:
                raise forms.ValidationError(u"'%s' is not a valid response_type." % type)
        
        return response_type

    def clean_redirect_uri(self):
        """
        :rfc 3.1.2: The redirect value has to match what was saved on the 
            authorization server.
        """
        redirect_uri = self.cleaned_data.get('redirect_uri')

        if redirect_uri:
            if not redirect_uri == self.client.redirect_uri:
                raise forms.ValidationError(_(u"'redirect_uri' doesn't match the 'client_id'."))
        
        return redirect_uri        
        
    def clean_scope(self):
        """
        :rfc 3.3: The scope of access requested by the client. This has to match
            what scopes are available. A user can accept, reject or grant a 
            different scope.
        """
        scope = self.cleaned_data.get('scope')
        scope = scope.split(' ')
        
        for s in scope:
            if s not in SCOPES:
                raise forms.ValidationError(_(u"'%s' is not a valid scope.") % s)
    
        return u' '.join(scope)
    
class AuthorizationForm(forms.Form):
    """
    A form used to ask the resource owner for authorization of a given client.
    """
    authorize = forms.BooleanField(initial = False)
    scope = forms.MultipleChoiceField()
    