import hashlib
import shortuuid
from django.conf import settings
from provider.constants import EXPIRE_DELTA, EXPIRE_DELTA_PUBLIC, EXPIRE_CODE_DELTA

from django.utils import timezone


def now():
    return timezone.now()


def short_token():
    """
    Generate a hash that can be used as an application identifier
    """
    hash = hashlib.sha1(shortuuid.uuid().encode('utf8'))
    hash.update(settings.SECRET_KEY.encode('utf8'))
    return hash.hexdigest()[::2]


def long_token():
    """
    Generate a hash that can be used as an application secret
    """
    hash = hashlib.sha1(shortuuid.uuid().encode('utf8'))
    hash.update(settings.SECRET_KEY.encode('utf8'))
    return hash.hexdigest()


def get_token_expiry(public=True):
    """
    Return a datetime object indicating when an access token should expire.
    Can be customized by setting :attr:`settings.OAUTH_EXPIRE_DELTA` to a
    :attr:`datetime.timedelta` object.
    """
    if public:
        return now() + EXPIRE_DELTA_PUBLIC
    else:
        return now() + EXPIRE_DELTA


def get_code_expiry():
    """
    Return a datetime object indicating when an authorization code should
    expire.
    Can be customized by setting :attr:`settings.OAUTH_EXPIRE_CODE_DELTA` to a
    :attr:`datetime.timedelta` object.
    """
    return now() + EXPIRE_CODE_DELTA
