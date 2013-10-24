from django.core.validators import URLValidator


def validate_uris(value):
    """
    Validates the `value` contains valid space separated urls"
    """
    v = URLValidator()
    for uri in value.split():
        v(uri)