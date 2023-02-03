
from django.conf import settings
from django.contrib import auth
from django.core.exceptions import ImproperlyConfigured
from django.utils.deprecation import MiddlewareMixin

from provider.oauth2.models import AccessToken

import logging
log = logging.getLogger(__name__)


class Oauth2UserMiddleware(MiddlewareMixin):
    """
    Middleware for using OAuth credentials to authenticate requests

    If the request user is not authenticated the request is checked for
    oauth2 tokens and authenticated based on their presence.

    This module functions much in the same way that
    django.contrib.auth.middleware.RemoteUserMiddleware does and depends on
    django.contrib.auth.backends.RemoteUserBackend being enabled in order to
    authenticate the session.
    """

    # Fixme: Not yet implemented
    def _http_access_token(self, request):

        try:
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            if not auth_header:
                return None
            parts = auth_header.split()
            if len(parts) != 2:
                return None
            scope, token = parts
            if scope.lower() == "bearer":
                return token
        except:
            log.exception("Unable to parse access token!")

    def process_request(self, request):
        # AuthenticationMiddleware is required
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "Authentication middleware is required for this module to work."
                " Insert 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before this Oauth2UserMiddleware class."
            )
        if 'django.contrib.auth.backends.RemoteUserBackend' not in settings.AUTHENTICATION_BACKENDS:
            raise ImproperlyConfigured(
                "Remote user authentication backend is required for this module to work."
                " Insert 'django.contrib.auth.backends.RemoteUserBackend' into the"
                " AUTHENTICATION_BACKENDS list in your settings."

            )
        try:
            access_token_http = self._http_access_token(request)
            access_token_get = request.GET.get('access_token', access_token_http)
            access_token = request.POST.get('access_token', access_token_get)

            if not access_token:
                return

            try:
                token = AccessToken.objects.get_token(access_token)
            except Exception as e:
                log.error("Invalid access token: {} - "
                          "{}: {}".format(access_token, e.__class__.__name__, e))
            else:
                user = auth.authenticate(remote_user=token.user.username)
                auth.login(request, user)
                request.oauth2_client = token.client
                request.oauth2_token = token
        except Exception as e:
            log.error("Oauth2UserMiddleware encountered an exception! "
                      "{}: {}".format(e.__class__.__name__, e))

    def process_response(self, request, response):
        if hasattr(request, 'oauth2_token'):
            # Set modified=False to prevent the session from being stored and the cookie from being sent
            request.session.modified = False
        return response
