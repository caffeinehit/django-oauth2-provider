from django.contrib import admin
from provider.oauth2 import models


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'token', 'expires',)
    raw_id_fields = ('user',)


class GrantAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'code', 'expires',)
    raw_id_fields = ('user',)


class ClientAdmin(admin.ModelAdmin):
    list_display = ('url', 'user', 'redirect_uri', 'client_id',
                    'client_type', 'auto_authorize')
    raw_id_fields = ('user',)


class AuthorizedClientAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'authorized_at')
    raw_id_fields = ('user',)


class AwsAccountAdmin(admin.ModelAdmin):
    list_display = ('arn', 'client', 'max_token_lifetime')
    raw_id_fields = ('acting_user',)


admin.site.register(models.AccessToken, AccessTokenAdmin)
admin.site.register(models.Grant, GrantAdmin)
admin.site.register(models.Client, ClientAdmin)
admin.site.register(models.AuthorizedClient, AuthorizedClientAdmin)
admin.site.register(models.AwsAccount, AwsAccountAdmin)
admin.site.register(models.RefreshToken)
admin.site.register(models.Scope)
