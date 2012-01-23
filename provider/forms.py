from django import forms

class OAuthValidationError(Exception):
    pass

class OAuthForm(forms.Form):
    """
    Custom form class that creates shallow error dicts.
    """
    def _clean_fields(self):
        """
        Overriding the default cleaning behaviour to exit early on errors instead
        of validating each field.        
        """
        try:
            super(OAuthForm, self)._clean_fields()
        except OAuthValidationError, e:
            self._errors.update(e.args[0])