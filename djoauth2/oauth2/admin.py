from django.contrib import admin
from .models import AccessToken, Grant, BasicClient, RefreshToken, Client


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'token', 'expires', 'scope',)
    raw_id_fields = ('user',)


class GrantAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'code', 'expires',)
    raw_id_fields = ('user',)


class ClientAdmin(admin.ModelAdmin):
    list_display = ('url', 'user', 'redirect_uri', 'client_id', 'client_type')
    raw_id_fields = ('user',)

admin.site.register(AccessToken, AccessTokenAdmin)
admin.site.register(Grant, GrantAdmin)
if Client == BasicClient:
    # Only if we are not overriding the BasicClient
    admin.site.register(BasicClient, ClientAdmin)
admin.site.register(RefreshToken)
