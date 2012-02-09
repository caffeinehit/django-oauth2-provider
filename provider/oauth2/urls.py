"""
The default implementation of the OAuth provider includes two public endpoints
that are meant for client (as defined in :draft:`1`) interaction. 

.. attribute:: ^authorize/$

    This is the URL where a client should redirect a user to for authorization.
    
    This endpoint expects the parameters defined in :draft:`4.1.1` and returns
    responses as defined in :draft:`4.1.2` and :draft:`4.1.2.1`.

.. attribute:: ^access_token/$

    This is the URL where a client exchanges a grant for an access tokens. 
    
    This endpoint expects different parameters depending on the grant type:
    
    * Access tokens: :draft:`4.1.3`
    * Refresh tokens: :draft:`6`
    * Password grant: :draft:`4.3.2`
    
    This endpoint returns responses depending on the grant type:
    
    * Access tokens: :draft:`4.1.4` and :draft:`5.1`
    * Refresh tokens: :draft:`4.1.4` and :draft:`5.1`
    * Password grant: :draft:`5.1`
    
    To override, remove or add grant types, override the appropriate methods on
    :class:`provider.views.AccessToken` and / or `provider.oauth2.views.AccessTokenView`.
    
    Errors are outlined in :draft:`5.2`.
    
"""

from django.conf.urls.defaults import patterns, url
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from provider.oauth2.views import Authorize, Redirect, Capture, AccessTokenView


urlpatterns = patterns('',
    url('^authorize/$', login_required(Capture.as_view()), name='authorize'),
    url('^authorize/2/$', login_required(Authorize.as_view()), name='authorize-2'),
    url('^redirect/$', login_required(Redirect.as_view()), name='redirect'),
    url('^access_token/$', csrf_exempt(AccessTokenView.as_view()), name='access_token'),
)
