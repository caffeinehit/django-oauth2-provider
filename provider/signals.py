import django.dispatch

access_token_fetched = django.dispatch.Signal(providing_args=['request', 'created', 'instance'])