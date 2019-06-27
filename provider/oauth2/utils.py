from __future__ import absolute_import

from datetime import timedelta

from django.utils.timezone import now

from ..constants import DEFAULT_SCOPES
from ..scope import to_names
from .models import Client
from .models import RefreshToken
from .models import AccessToken


def create_access_and_refresh_token(client, user, scope=None):
    scope = scope or DEFAULT_SCOPES[2][0] # read+write

    access_token = AccessToken.objects.create(
        client=client,
        user=user,
        scope=scope
    )
    refresh_token = RefreshToken.objects.create(
        client=client,
        user=user,
        access_token=access_token,
    )
    return {
        'access_token': access_token.token,
        'refresh_token': refresh_token.token,
        'expires_at': access_token.expires_text,
        'scope': ' '.join(to_names(access_token.scope)),
    }


def expire_user_access_tokens(user):
    """Expire all active tokens associated with a user"""
    current_ts = now()
    expire_ts = current_ts - timedelta(minutes=1)
    AccessToken.objects.filter(user=user, expires__gte=current_ts).update(expires=expire_ts)
