from django.urls import path, include
from django.contrib import admin

admin.autodiscover()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('oauth2/', include('provider.oauth2.urls', namespace='oauth2')),
    path('tests/', include('provider.oauth2.tests.urls', namespace='tests')),
]
