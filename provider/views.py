# Create your views here.
from django.core.urlresolvers import reverse
from django.http import HttpResponseBadRequest, HttpResponse, \
    HttpResponseRedirect, HttpResponseForbidden, QueryDict
from django.utils.translation import ugettext_lazy as _
from django.views.generic.base import TemplateView, View
from provider.constants import ENFORCE_SECURE, SESSION_KEY
import urlparse

class Mixin(object):
    """
    Common methods required on the views below
    """
    def get_data(self, request, key = 'params'):
        return request.session['%s:%s' % (SESSION_KEY, key)]
    
    def cache_data(self, request, data, key = 'params'):
        request.session['%s:%s' % (SESSION_KEY, key)] = data
    
    def authenticate(self, request):
        """
        Authenticate a client against all the backends configured in 
        :attr:`authentication`.
        """
        for backend in self.authentication:
            client = backend().authenticate(request)
            if client is not None:
                return client
        return None

class Capture(View):
    """
    As stated in section 3.1.2.5 this view captures all the request 
    parameters and redirects to another URL to avoid any leakage of request
    parameters to potentially harmful JavaScripts.
    
    This application assumes that whatever web-server is used as front-end will
    handle SSL transport.
        
    If you want strict enforcement of secure communication at application level, 
    set :settings:`OAUTH_ENFORCE_SECURE` to ``True``.
       
    The actual implementation is required to override :method:`authorize_redirect`.
    """

    def get_redirect_url(self):
        """
        Return a :class:`HttpResponseRedirect` object to the view handling the
        resource owner's client authorization.
        """
        raise NotImplementedError
    
    def handle(self, request, data):
        if ENFORCE_SECURE and not request.is_secure():
            return HttpResponseBadRequest("A secure connection is required.")

        if not 'response_type' in data:
            return HttpResponseBadRequest("No 'response_type' indicated.")
        
        self.cache_data(request, data)

        return HttpResponseRedirect(self.get_redirect_url())
        
    def get(self, request):
        return self.handle(request, request.GET)

    def post(self, request):
        return self.handle(request, request.POST)
    


class Authorize(TemplateView, Mixin):
    def get_redirect_url(self):
        """
        Return a URL to the view handling the final redirection to the client
        that initiated the authorization.
        """
        raise NotImplementedError
    
    def get_request_form(self, client, data):
        """
        Return a form that is capable of validating the request data captured
        by the :class:`Capture` view.
        The form must accept a keyword argument ``client``.
        """
        raise NotImplementedError
    
    def get_authorization_form(self, request, client, data, client_data):
        """
        Return a form that is capable of authorizing the client to use the 
        owner resource.
        """
        raise NotImplementedError
    
    def get_client(self, client_id):
        """
        Return a client object from a given client identifier. Return ``None``
        if the client id couldn't be found.
        """
        raise NotImplementedError

    def save_authorization(self, request, client, form, client_data):
        """
        Save the authorization that the user granted to the client, involving
        the creation of a time limited authorization code. 
        """
        raise NotImplementedError

    def _validate_client(self, request):
        data = self.get_data(request)

        client = self.get_client(data.get('client_id'))
        
        if client is None:
            return self.render_to_response({'error': True, 'form': None,
                'message': _("No such client.")})

        self.cache_data(request, client, 'client')

        form = self.get_request_form(client, data)
        
        if not form.is_valid():
            return form

        return client, form.cleaned_data
    
    def _client_validation_error(self, form):
        return self.render_to_response({'error': True, 'form': form,
            'message': _("Client request parameter validation failed.")})
    
    def get(self, request):
        try:
            result_or_form = self._validate_client(request)
            client, cleaned_data = result_or_form
        except ValueError: # Unpacking failed
            return self._client_validation_error(result_or_form)

        authorization_form = self.get_authorization_form(request, client, None, 
            cleaned_data)

        return self.render_to_response({'form': authorization_form})
        
    def post(self, request):
        try:
            result_or_form = self._validate_client(request)
            client, cleaned_data = result_or_form
        except ValueError: # Unpacking failed
            return self._client_validation_error(result_or_form)
        
        authorization_form = self.get_authorization_form(request, client,
            request.POST, cleaned_data)
        
        if not authorization_form.is_valid():
            return self.render_to_response({'form': authorization_form})
        
        self.save_authorization(request, client, authorization_form, cleaned_data)
        # Make sure we're caching the cleaned data from now on
        self.cache_data(request, cleaned_data)
        
        return HttpResponseRedirect(self.get_redirect(request))
    
class Redirect(TemplateView):
    """
    Redirect the user back to the client.
    """
    def get(self, request):
        data = self.get_data(request)
        client = self.get_client(data.get('client_id'))

        redirect_uri = data.get('redirect_uri', client.redirect_uri)

        if 'state' in data:        
            # Sometimes I hate tuples for being immutable...
            parsed = urlparse.urlparse(redirect_uri)
            query = QueryDict(parsed.query, mutable = True)
            query['state'] = data.get('state')
            newparsed = parsed[:4] + (query.urlencode(),) + parsed[5:]
            redirect_uri = urlparse.ParseResult(*newparsed).geturl()
        
        return HttpResponseRedirect(redirect_uri)        

class AccessToken(View, Mixin):    
    """
    According to the RFC this endpoint too must require the use of secure 
    communication.
    
    If you want strict enforcement of secure communication at application level,
    set :settings:`OAUTH_ENFORCE_SECURE` to ``True``.
    
    According to :rfc 3.2: we can only accept POST requests.
    """
    
    authentication = ()
    
    def post(self, request):
        if ENFORCE_SECURE and not request.is_secure():
            return HttpResponseBadRequest()

        client = self.authenticate(request)
        
        if client is None:
            return HttpResponseForbidden()
        
        

        return HttpResponse()
    
        
        