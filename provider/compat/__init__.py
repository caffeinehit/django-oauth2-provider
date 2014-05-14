from unittest import skipIf

from django.conf import settings
from django.contrib.contenttypes.generic import get_model


user_model_label = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
user_model_class = lambda: get_model(*user_model_label.split('.'))

try:
    from django.contrib.auth.tests.utils import skipIfCustomUser
except ImportError:
    def skipIfCustomUser(wrapped):
        return skipIf(settings.AUTH_USER_MODEL != 'auth.User', 'Custom user model in use')(wrapped)
