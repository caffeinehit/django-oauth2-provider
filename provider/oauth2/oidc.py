from calendar import timegm
import datetime

from django.conf import settings
import jwt

from .. import constants
from provider import scope


def get_id_token(access_token, nonce):
    """
    Creates an ID token according to http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation.

    Returns JWS encoded with client's secret key.

    Arguments
      access_token (AccessToken) -- access token from which ID token should be created
      nonce (str) -- CSRF protection data
    """
    client = access_token.client

    id_token = {}

    # Set issuer
    id_token['iss'] = settings.OAUTH_OIDC_ISSUER

    # Set audience
    id_token['aud'] = client.client_id

    # Set current/issued time
    now = datetime.datetime.utcnow()
    id_token['iat'] = timegm(now.utctimetuple())

    # Set expiration time
    expires = now + datetime.timedelta(seconds=getattr(settings, 'OAUTH_ID_TOKEN_EXPIRATION', 30))
    id_token['exp'] = timegm(expires.utctimetuple())

    # CSRF protection
    id_token['nonce'] = nonce

    # Add profile details
    if scope.check(constants.PROFILE, access_token.scope):
        user = access_token.user
        id_token.update({
            'name': user.get_full_name(),
            'given_name': user.first_name,
            'family_name': user.last_name,
            'email': user.email,
            'preferred_username': user.username
        })

    # Encode the data to a JWT
    id_token = jwt.encode(id_token, client.client_secret)

    return id_token
