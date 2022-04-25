from django.urls import re_path, include
from django.contrib import admin

admin.autodiscover()

urlpatterns = [
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^oauth2/', include('provider.oauth2.urls', namespace='oauth2')),
]
