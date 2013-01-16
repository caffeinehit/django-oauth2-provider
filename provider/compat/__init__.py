try:
    from django.contrib.auth.tests.utils import skipIfCustomUser
except ImportError:
    def skipIfCustomUser(wrapped):
        return wrapped
