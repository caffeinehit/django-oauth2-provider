from django import template
from .. import scope

register = template.Library()


@register.filter
def scopes(scope_int):
    """
    Wrapper around :attr:`provider.scope.names` to turn an int into a list
    of scope names in templates.
    """
    return scope.to_names(scope_int)
