from django import forms

class OAuthValidationError(Exception):
    pass

class OAuthForm(forms.Form):
    """
    Custom form class that creates shallow error dicts.
    """
    def __init__(self, *args, **kwargs):
        self.client = kwargs.pop('client', None)
        super(OAuthForm, self).__init__(*args, **kwargs)
        
    def _clean_fields(self):
        """
        Overriding the default cleaning behaviour to exit early on errors instead
        of validating each field.        
        """
        try:
            super(OAuthForm, self)._clean_fields()
        except OAuthValidationError, e:
            self._errors.update(e.args[0])

    def _clean_form(self):
        """
        Overriding the default cleaning behaviour for a shallow error dict.
        """
        try:
            super(OAuthForm, self)._clean_form()
        except OAuthValidationError, e:
            self._errors.update(e.args[0])
