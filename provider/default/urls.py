from django.conf.urls.defaults import patterns, url
from django.contrib.auth.decorators import login_required


urlpatterns = patterns('',
    url('^authenticate/$', login_required(Authenticate.as_view()), name = 'authenticate'),
    url('^authorize/$', login_required(Authorize.as_view()), name = 'authorize'),
    url('^redirect/$', login_required(Redirect.as_view()), name = 'redirect'),
    url('^access_token/$', AccessToken.as_view(), name = 'access_token'),
    
)