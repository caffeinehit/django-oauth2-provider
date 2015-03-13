
from django.contrib import auth
from django.core.exceptions import ImproperlyConfigured

from provider.oauth2.models import AccessToken

import logging
log = logging.getLogger(__name__)

class Oauth2UserMiddleware(object):
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
        return None

    def process_request(self, request):
        # AuthenticationMiddleware is required
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "Authentication middleware is required for this module to work."
                " Insert 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before this Oauth2UserMiddleware class."
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
        except Exception as e:
            log.error("Oauth2UserMiddleware encountered an exception! "
                      "{}: {}".format(e.__class__.__name__, e))
