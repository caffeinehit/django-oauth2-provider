from django.contrib import admin
from provider.oauth2.models import AccessToken, Grant, Client, \
    RefreshToken
    
class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'token', 'expires', 'scope',)

class GrantAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'code', 'expires',)
    
class ClientAdmin(admin.ModelAdmin):    
    list_display = ('user', 'url', 'redirect_uri', 'client_id', 'client_type')

admin.site.register(AccessToken, AccessTokenAdmin)
admin.site.register(Grant, GrantAdmin)
admin.site.register(Client, ClientAdmin)
admin.site.register(RefreshToken)
