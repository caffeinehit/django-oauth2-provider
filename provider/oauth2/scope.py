"""
Default scope implementation relying on bit shifting. See 
:attr:`provider.constants.SCOPES` for the list of available scopes.

Scopes can be combined, such as ``"read write"``. Note that a single ``"write"``
scope is *not* the same as ``"read write"``.

See :class:`provider.oauth2.forms.ScopeMixin` on how scopes are
combined.
"""

from provider.constants import SCOPES

SCOPE_NAMES = [(name, name) for (value, name) in SCOPES]
SCOPE_NAME_DICT = dict([(name, value) for (value, name) in SCOPES])
SCOPE_VALUE_DICT = dict([(value, name) for (value, name) in SCOPES])

def check(wants, has):
    """
    Check if a desired scope ``wants`` is part of an available scope ``has``.
    
    Returns ``False`` if not, return ``True`` if yes.
    
    :example:
        
    If a list of scopes such as
    
    ::
    
        READ = 1 << 1
        WRITE = 1 << 2
        READ_WRITE = READ | WRITE
    
        SCOPES = (
            (READ, 'read'),
            (WRITE, 'write'),
            (READ_WRITE, 'read+write'),
        )
    
    is defined, we can check if a given scope is part of another:
    
    ::
    
        >>> from provider.oauth2 import scope
        >>> scope.check(READ, READ)
        True
        >>> scope.check(WRITE, READ)
        False
        >>> scope.check(WRITE, WRITE)
        True
        >>> scope.check(READ, WRITE)
        False
        >>> scope.check(READ, READ_WRITE)
        True
        >>> scope.check(WRITE, READ_WRITE)
        True        
    
    """
    if wants & has == 0:
        return False
    if wants & has < wants:
        return False
    return True
