from django.contrib.auth.models import AbstractUser, UserManager

class MyManager(UserManager):
    pass

class User(AbstractUser):
    objects = MyManager()
