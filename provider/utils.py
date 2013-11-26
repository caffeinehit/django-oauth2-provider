import hashlib
import shortuuid
from datetime import datetime, tzinfo
from django.conf import settings
from django.utils import dateparse
from django.db.models.fields import (DateTimeField, DateField,
                                     EmailField, TimeField,
                                     FieldDoesNotExist)
from django.core.serializers.json import DjangoJSONEncoder
from .constants import EXPIRE_DELTA, EXPIRE_DELTA_PUBLIC, EXPIRE_CODE_DELTA

try:
    import json
except ImporError:
    import simplejson as json

try:
    from django.utils import timezone
except ImportError:
    timezone = None

def now():
    if timezone:
        return timezone.now()
    else:
        # Django 1.3 compatibility
        return datetime.now()


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


def serialize_instance(instance):
    """
    Since Django 1.6 items added to the session are no longer pickled,
    but JSON encoded by default. We are storing partially complete models
    in the session (user, account, token, ...). We cannot use standard
    Django serialization, as these are models are not "complete" yet.
    Serialization will start complaining about missing relations et al.
    """
    ret = dict([(k, v)
                for k, v in instance.__dict__.items()
                if not k.startswith('_')])
    return json.loads(json.dumps(ret, cls=DjangoJSONEncoder))


def deserialize_instance(model, data={}):
    "Translate raw data into a model instance."
    ret = model()
    for k, v in data.items():
        if v is not None:
            try:
                f = model._meta.get_field(k)
                if isinstance(f, DateTimeField):
                    v = dateparse.parse_datetime(v)
                elif isinstance(f, TimeField):
                    v = dateparse.parse_time(v)
                elif isinstance(f, DateField):
                    v = dateparse.parse_date(v)
            except FieldDoesNotExist:
                pass
        setattr(ret, k, v)
    return ret
