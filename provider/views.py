# Create your views here.
from django.http import HttpResponseBadRequest, HttpResponse, \
    HttpResponseRedirect, HttpResponseForbidden, QueryDict
from django.utils.translation import ugettext as _
from django.views.generic.base import TemplateView, View
from provider import constants
import json
import urlparse

class OAuthError(Exception):
    """
    Throw this error if an exception occurs that you want to be signalled to the
    client.
    """

class OAuthView(TemplateView):
    """ Overriding dispatch method to add no caching headers to each 
    response. """
    def dispatch(self, request, *args, **kwargs):
        response = super(OAuthView, self).dispatch(request, *args, **kwargs)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'
        return response

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

class Capture(OAuthView, Mixin):
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


class Authorize(OAuthView, Mixin):
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
            raise OAuthError({
                'error': 'unauthorized_client',
                'error_description': _("An unauthorized client tried to access"
                    " your resources.")
            })

        form = self.get_request_form(client, data)

        if not form.is_valid():
            raise OAuthError(form.errors)

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
        
        try:
            client, data = self._validate_client(request, data)
        except OAuthError, e:
            return self.error_response(request, e.args[0], status=400)

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
        
      
    
class Redirect(OAuthView, Mixin):
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

class AccessToken(OAuthView, Mixin):    
    """
    According to the RFC this endpoint too must require the use of secure 
    communication.
    
    If you want strict enforcement of secure communication at application level,
    set :settings:`OAUTH_ENFORCE_SECURE` to ``True``.
    
    According to :rfc 3.2: we can only accept POST requests.
    """
    
    authentication = ()
    grant_types = ['authorization_code', 'refresh_token', 'password']
    
    def get_authorization_code_grant(self, request, data, client):
        """
        Return the grant associated with this request or an error dict.
        :return tuple: ``(True or False, grant or error_dict)``
        """
        raise NotImplementedError
    
    def get_refresh_token_grant(self, request, data, client):
        """
        Return the refresh token associated with this request or an error dict.
        :return tuple: ``(True or False, token or error_dict)``
        """
        raise NotImplementedError
    
    def get_password_grant(self, request, data, client):
        """
        Return a user associated with this request or an error dict.
        :return tuple: ``(True or False, user or error_dict)``
        """
        raise NotImplementedError
        
    
    def create_access_token(self, request, user, scope, client):
        """
        Override to handle access token creation.
        
        :return obj: Access token
        """
        raise NotImplementedError
    
    def create_refresh_token(self, request, user, scope, access_token, client):
        """
        Override to handle refresh token creation.
        
        :return obj: Refresh token
        """
        raise NotImplementedError
    
    def invalidate_grant(self, grant):
        """
        Override to handle grant invalidation. A grant is invalidated right after
        creating an access token from it.
        
        :return None:
        """
        raise NotImplementedError
    
    def invalidate_refresh_token(self, refresh_token):
        """
        Override to handle refresh token invalidation. When requesting a new
        access token from a refresh token, the old one is *always* invalidated.
        
        :return None:
        """
        raise NotImplementedError
    
    def invalidate_access_token(self, access_token):
        """
        Override to handle access token invalidation. When a new access token
        is created from a refresh token, the old one is *always* invalidated.
        
        :return None:
        """
        raise NotImplementedError
    
    def error_response(self, error, mimetype='application/json', status=400, **kwargs):
        return HttpResponse(json.dumps(error), mimetype=mimetype, status=status, **kwargs)        
    
    def access_token_response(self, access_token):
        return HttpResponse(
            json.dumps({
                'access_token': access_token.token,
                'expires_in': access_token.get_expire_delta(),
                'refresh_token': access_token.refresh_token.token,
                'scope': access_token.scope
            }), mimetype='application/json'
        )
    
    def authorization_code(self, request, data, client):
        """
        Handle ``grant_type=authorization_token`` requests.
        """
        grant = self.get_authorization_code_grant(request, request.POST, client)
        
        at = self.create_access_token(request, grant.user, grant.scope, client)
        rt = self.create_refresh_token(request, grant.user, grant.scope, at, client)
        
        self.invalidate_grant(grant)
        
        return self.access_token_response(at)        
        
        
    def refresh_token(self, request, data, client):
        """
        Handle ``grant_type=refresh_token`` requests.
        """
        rt = self.get_refresh_token_grant(request, data, client)
        
        self.invalidate_refresh_token(rt)
        self.invalidate_access_token(rt.access_token)
        
        at = self.create_access_token(request, rt.user, rt.access_token.scope, client)
        rt = self.create_refresh_token(request, at.user, at.scope, at, client)
        
        return self.access_token_response(at)
    
    def password(self, request, data, client):
        """
        Handle ``grant_type=password`` requests
        """
        
        data = self.get_password_grant(request, data, client)
        
        at = self.create_access_token(request, data.get('user'), data.get('scope'), client)
        rt = self.create_refresh_token(request, data.get('user'), data.get('scope'), at, client)
        
        return self.access_token_response(at)
        
    def get_handler(self, grant_type):
        """
        Return a function or method that is capable handling the 'grant_type'
        requested by the client.
        """
        if grant_type == 'authorization_code':
            return self.authorization_code
        elif grant_type == 'refresh_token':
            return self.refresh_token
        elif grant_type == 'password':
            return self.password
        return None
    
    def get(self, request):
        """
        As per :rfc 3.2: the token endpoint *only* supports POST requests.
        """
        return self.error_response({'error': 'invalid_request',
            'error_description': _("Only POST requests allowed.")})
    
    def post(self, request):
        """
        As per :rfc 3.2: the token endpoint *only* supports POST requests.
        """
        if constants.ENFORCE_SECURE and not request.is_secure():
            return self.error_response({'error': 'invalid_request',
                'error_description': _("A secure connection is required.")})

        if not 'grant_type' in request.POST:
            return self.error_response({'error': 'invalid_request',
                'error_description': _("No 'grant_type' included in the request.")})
            
        grant_type = request.POST['grant_type']
        
        if grant_type not in self.grant_types:
            return self.error_response({'error': 'unsupported_grant_type'})
    
        client = self.authenticate(request)
        
        if client is None:
            return self.error_response({'error': 'invalid_client'})
        
        handler = self.get_handler(grant_type)
        
        try:
            return handler(request, request.POST, client)
        except OAuthError, e:
            return self.error_response(e.args[0])
        
        
