from datetime import datetime, tzinfo
from django.conf import settings
from .constants import EXPIRE_DELTA, EXPIRE_CODE_DELTA
from django.utils.timezone import now
from django.utils.crypto import get_random_string

def short_token(length=16):
    """
    Generate a hash that can be used as an application identifier
    """
    return get_random_string(length)


def long_token(length=32):
    """
    Generate a hash that can be used as an application secret
    """
    return get_random_string(length)


def get_token_expiry():
    """
    Return a datetime object indicating when an access token should expire.
    Can be customized by setting :attr:`settings.OAUTH_EXPIRE_DELTA` to a
    :attr:`datetime.timedelta` object.
    """
    return now() + EXPIRE_DELTA


def get_code_expiry():
    """
    Return a datetime object indicating when an authorization code should
    expire.
    Can be customized by setting :attr:`settings.OAUTH_EXPIRE_CODE_DELTA` to a
    :attr:`datetime.timedelta` object.
    """
    return now() + EXPIRE_CODE_DELTA
