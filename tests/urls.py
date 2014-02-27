from djoauth2.compat.urls import *
from django.contrib import admin

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^oauth2/', include('djoauth2.oauth2.urls', namespace = 'oauth2')),
)
