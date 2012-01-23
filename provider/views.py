# Create your views here.
from django.http import HttpResponseBadRequest, HttpResponse, \
    HttpResponseRedirect, HttpResponseForbidden, QueryDict
from django.utils.translation import ugettext_lazy as _
from django.views.generic.base import TemplateView, View
from provider import constants
import json
import urlparse

class Mixin(object):
    """
    Common methods required on the views below
    """
    def get_data(self, request, key='params'):
        return request.session.get('%s:%s' % (constants.SESSION_KEY, key))
    
    def cache_data(self, request, data, key='params'):
        request.session['%s:%s' % (constants.SESSION_KEY, key)] = data
    
    def clear_data(self, request):
        for key in request.session.keys():
            if key.startswith(constants.SESSION_KEY):
                del request.session[key]
    
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
    


class Capture(TemplateView, Mixin):
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
    template_name = 'provider/authorize.html'

    def get_redirect_url(self, request):
        """
        Return a :class:`HttpResponseRedirect` object to the view handling the
        resource owner's client authorization.
        """
        raise NotImplementedError
    
    def handle(self, request, data):
        self.cache_data(request, data)

        if constants.ENFORCE_SECURE and not request.is_secure():
            return self.render_to_response({'error': 'access_denied',
                'error_description': _("A secure connection is required."),
                'next': None},
                status=400)

        return HttpResponseRedirect(self.get_redirect_url(request))
        
    def get(self, request):
        return self.handle(request, request.GET)

    def post(self, request):
        return self.handle(request, request.POST)
    


class Authorize(TemplateView, Mixin):
    template_name = 'provider/authorize.html'
    
    def get_redirect_url(self, request):
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
        
        Should return ``None`` in case authorization is not granted and 
        a string representing the authorization code.
        
        :return: ``None``, ``str``
        """
        raise NotImplementedError

    def _validate_client(self, request, data):
        """
        :return tuple: ``(client or False, data or error)`` 
        """
        client = self.get_client(data.get('client_id'))
        
        if client is None:
            return False, {
                'error': 'unauthorized_client',
                'error_description': _("An unauthorized client tried to access"
                    " your resources.")
            }

        form = self.get_request_form(client, data)
        
        if not form.is_valid():
            # We expect a shallow form.errors dict:
            # {'error': 'reason', 'error_description': 'Something'}
            return False, form.errors

        return client, form.cleaned_data
    
    def error_response(self, request, error, **kwargs):
        """
        :param error: dict
        """
        ctx = {}
        ctx.update(error)

        # If we got a malicious redirec_uri or client_id, remove all the cached 
        # data and tell the resource owner. We will *not* redirect back to the 
        # URL.
        
        if error['error'] in ['redirect_uri', 'unauthorized_client']:
            ctx.update(next='/')
            return self.render_to_response(ctx, **kwargs)
        
        ctx.update(next=self.get_redirect_url(request))

        return self.render_to_response(ctx, **kwargs)

    def handle(self, request, post_data=None):
        data = self.get_data(request)
        
        if data is None:
            return self.error_response(request, {'expired_authorization': True})
        
        client, data = self._validate_client(request, data)

        if not client:
            return self.error_response(request, data, status=403)   


        authorization_form = self.get_authorization_form(request, client, post_data,
            data)

        if not authorization_form.is_bound:
            return self.render_to_response({'form': authorization_form})
        
        if not authorization_form.is_valid():
            return self.render_to_response({'form': authorization_form})
        
        code = self.save_authorization(request, client, authorization_form, data)

        self.cache_data(request, data)
        self.cache_data(request, code, "code")
        self.cache_data(request, client, "client")
        
        return HttpResponseRedirect(self.get_redirect_url(request))

    def get(self, request):
        return self.handle(request, None)        
        
    def post(self, request):
        return self.handle(request, request.POST)
        
      
    
class Redirect(TemplateView, Mixin):
    """
    Redirect the user back to the client.
    """
    def get(self, request):
        data = self.get_data(request)
        code = self.get_data(request, "code")
        error = self.get_data(request, "error")
        client = self.get_data(request, "client")

        self.clear_data(request)

        redirect_uri = data.get('redirect_uri', client.redirect_uri)

        parsed = urlparse.urlparse(redirect_uri)

        query = QueryDict('', mutable=True)
        
        if 'state' in data:
            query['state'] = data['state']
        
        if error is not None:
            query.update(error)
        elif code is None:
            query['error'] = 'access_denied'
        else:
            query['code'] = code
        
        parsed = parsed[:4] + (query.urlencode(), '')

        redirect_uri = urlparse.ParseResult(*parsed).geturl()
                
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
    
    def get_grant(self, request, data, client):
        """
        Return the grant associated with this request, or an error dict.
        :return tuple: ``(True or False, grant or error_dict)``
        """
        raise NotImplementedError
    
    def create_access_token(self, request, grant, client):
        raise NotImplementedError
    
    def create_refresh_token(self, request, grant, access_token, client):
        raise NotImplementedError
    
    def invalidate_grant(self, grant):
        raise NotImplementedError
    
    def error_response(self, error, mimetype='application/json', status=403, **kwargs):
        return HttpResponse(json.dumps(error), mimetype=mimetype, status=status, **kwargs)
    
    def post(self, request):
        if constants.ENFORCE_SECURE and not request.is_secure():
            return HttpResponseBadRequest()

        client = self.authenticate(request)
        
        if client is None:
            return self.error_response({'error': 'invalid_client'})
        
        valid, grant_or_error = self.get_grant(request, request.POST, client)
        
        if not valid:
            return self.error_response(grant_or_error)
        
        at = self.create_access_token(request, grant_or_error, client)
        rt = self.create_refresh_token(request, grant_or_error, at, client)
        
        self.invalidate_grant(grant_or_error)
        
        return HttpResponse(
            json.dumps({
                'access_token': at.token,
                'expires_in': at.get_expire_delta(),
                'refresh_token': rt.token,
                'scope': at.scope
            }), mimetype='application/json'
        )

    
        
        
