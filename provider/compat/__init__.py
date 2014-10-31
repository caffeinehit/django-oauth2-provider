from django.conf import settings
from django.db.models.loading import get_model


user_model_label = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
user_model_class = lambda: get_model(*user_model_label.split('.'))
user_model_db_table = lambda: user_model_class()._meta.db_table or 'auth_user'


try:
    from django.contrib.auth.tests.utils import skipIfCustomUser
except ImportError:
    def skipIfCustomUser(wrapped):
        return wrapped
