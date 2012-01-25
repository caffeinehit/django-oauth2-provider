from provider.constants import SCOPES

SCOPE_NAMES = [(name, name) for (value, name) in SCOPES]
SCOPE_NAME_DICT = dict([(name, value) for (value, name) in SCOPES])
SCOPE_VALUE_DICT = dict([(value, name) for (value, name) in SCOPES])

def check(wants, has):
    if wants & has == 0:
        return False
    if wants & has < wants:
        return False
    return True
