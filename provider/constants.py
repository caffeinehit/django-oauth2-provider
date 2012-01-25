from datetime import timedelta
from django.conf import settings

CONFIDENTIAL = 0
PUBLIC = 1

CLIENT_TYPES = (
    (CONFIDENTIAL, "Confidential (Web applications)"),
    (PUBLIC, "Public (Native and JS applications)")
)

RESPONSE_TYPE_CHOICES = getattr(settings, 'OAUTH_RESPONSE_TYPE_CHOICES', ("code", "token"))

READ = 1 << 1
WRITE = 1 << 2  

DEFAULT_SCOPES = (
    (READ, 'read'),
    (WRITE, 'write'),
)

SCOPES = getattr(settings, 'OAUTH_SCOPES', DEFAULT_SCOPES)

EXPIRE_DELTA = getattr(settings, 'OAUTH_EXPIRE_DELTA', timedelta(days=365))

EXPIRE_CODE_DELTA = getattr(settings, 'OAUTH_EXPIRE_CODE_DELTA', timedelta(seconds=10 * 60))

ENFORCE_SECURE = getattr(settings, 'OAUTH_ENFORCE_SECURE', False)
ENFORCE_CLIENT_SECURE = getattr(settings, 'OAUTH_ENFORCE_CLIENT_SECURE', True)

SESSION_KEY = getattr(settings, 'OAUTH_SESSION_KEY', 'oauth')
