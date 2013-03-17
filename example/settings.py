from datetime import timedelta

SECRET_KEY = "=x3ae$i^3_@4#%_@5h!b8f=_84)@l$@d^&amp;zavds!%jq#rob1ga"

INSTALLED_APPS = (
	'provider',
	'provider.oauth2',
)

OAUTH_EXPIRE_DELTA = timedelta(30)  # 1 month