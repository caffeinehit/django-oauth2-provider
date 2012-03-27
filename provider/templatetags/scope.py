from django import template
from provider import scope

register = template.Library()

@register.filter
def scopes(scope_int):
    """ 
    Wrapper around :attr:`provider.scope.names` to turn an int into a list
    of scope names in templates.
    """
    return scope.names(scope_int)
