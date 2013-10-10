from django.dispatch import Signal


log_in = Signal(providing_args=['user'])
token_auth = Signal(providing_args=['user'])
