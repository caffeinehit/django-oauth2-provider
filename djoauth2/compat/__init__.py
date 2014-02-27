from django.conf import settings


user_model_label = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')


try:
    from django.contrib.auth.tests.utils import skipIfCustomUser
except ImportError:
    def skipIfCustomUser(wrapped):
        return wrapped
