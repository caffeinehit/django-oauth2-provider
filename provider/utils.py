from datetime import datetime
from django.conf import settings
from provider.constants import EXPIRE_DELTA, EXPIRE_CODE_DELTA
import hashlib
import shortuuid


def short_token():
    """
    Generate a hash that can be used as an application identifier
    """
    hash = hashlib.sha1(shortuuid.uuid())
    hash.update(settings.SECRET_KEY)
    return hash.hexdigest()[::2]

def long_token():
    """
    Generate a hash that can be used as an application secret
    """
    hash = hashlib.sha1(shortuuid.uuid())
    hash.update(settings.SECRET_KEY)
    return hash.hexdigest()
    
def get_token_expiry():
    """
    Return a datetime object indicating when an access token should expire. 
    Can be customized by setting :attr:`settings.OAUTH_EXPIRE_DELTA` to a 
    :attr:`datetime.timedelta` object.
    """
    return datetime.now() + EXPIRE_DELTA

def get_code_expiry():
    """
    Return a datetime object indicating when an authorization code should 
    expire.
    Can be customized by setting :attr:`settings.OAUTH_EXPIRE_CODE_DELTA` to a 
    :attr:`datetime.timedelta` object.
    """
    return datetime.now() + EXPIRE_CODE_DELTA

