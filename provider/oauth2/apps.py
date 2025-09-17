from django.apps import AppConfig

class Oauth2(AppConfig):
    name = 'provider.oauth2'
    label = 'oauth2'
    verbose_name = "Provider Oauth2"

    def ready(self):
        import provider.oauth2.signals
