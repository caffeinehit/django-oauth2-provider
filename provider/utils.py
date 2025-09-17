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


class BadArn(Exception):
    pass


class ArnHelper:
    def __init__(self, arn):
        self.arn = arn
        parts = arn.split(':')
        if len(parts) != 6:
            raise BadArn("Arn must have 6 parts")
        if parts[:2] != ['arn', 'aws']:
            raise BadArn("Arn must start with 'arn:aws:...'")

        if parts[2] not in ['iam', 'sts']:
            raise BadArn("Arn must come from 'iam' or 'sts' service")

        self.service = parts[2]
        self.account_id = parts[4]
        self.entity_ref = parts[5]
        entity_parts = self.entity_ref.split('/')
        self.type = entity_parts[0]
        self.general_type = self.type if self.type != "assumed-role" else "role"
        self.name = entity_parts[1]
        self.session = entity_parts[2] if len(entity_parts) > 2 else None

    def __eq__(self, other):
        if not isinstance(other, ArnHelper):
            return False

        if self.account_id == other.account_id and self.general_type == other.general_type and self.name == other.name:
            return True

        return False
