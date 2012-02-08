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
