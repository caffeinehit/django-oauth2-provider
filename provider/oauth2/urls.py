"""
The default implementation of the OAuth provider includes two public endpoints
that are meant for client (as defined in :rfc:`1`) interaction.

.. attribute:: ^authorize/$

    This is the URL where a client should redirect a user to for authorization.

    This endpoint expects the parameters defined in :rfc:`4.1.1` and returns
    responses as defined in :rfc:`4.1.2` and :rfc:`4.1.2.1`.

.. attribute:: ^access_token/$

    This is the URL where a client exchanges a grant for an access tokens.

    This endpoint expects different parameters depending on the grant type:

    * Access tokens: :rfc:`4.1.3`
    * Refresh tokens: :rfc:`6`
    * Password grant: :rfc:`4.3.2`

    This endpoint returns responses depending on the grant type:

    * Access tokens: :rfc:`4.1.4` and :rfc:`5.1`
    * Refresh tokens: :rfc:`4.1.4` and :rfc:`5.1`
    * Password grant: :rfc:`5.1`

    To override, remove or add grant types, override the appropriate methods on
    :class:`provider.views.AccessToken` and / or
    :class:`provider.oauth2.views.AccessTokenView`.

    Errors are outlined in :rfc:`5.2`.

"""

from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.urls import path
from provider.oauth2 import views

app_name = 'oauth2'

urlpatterns = [
    path('authorize',
        login_required(views.CaptureView.as_view()),
        name='capture'),
    path('authorize/confirm',
        login_required(views.AuthorizeView.as_view()),
        name='authorize'),
    path('redirect',
        login_required(views.RedirectView.as_view()),
        name='redirect'),
    path('access_token',
        csrf_exempt(views.AccessTokenView.as_view()),
        name='access_token'),
]
