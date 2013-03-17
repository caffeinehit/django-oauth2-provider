from django import forms


class OAuthValidationError(Exception):
    """
    Exception to throw inside :class:`OAuthForm` if any OAuth2 related errors
    are encountered such as invalid grant type, invalid client, etc.

    :attr:`OAuthValidationError` expects a dictionary outlining the OAuth error
    as its first argument when instantiating.

    :example:

    ::

        class GrantValidationForm(OAuthForm):
            grant_type = forms.CharField()

            def clean_grant(self):
                if not self.cleaned_data.get('grant_type') == 'code':
                    raise OAuthValidationError({
                        'error': 'invalid_grant',
                        'error_description': "%s is not a valid grant type" % (
                            self.cleaned_data.get('grant_type'))
                    })

    The different types of errors are outlined in :rfc:`4.2.2.1` and
    :rfc:`5.2`.
    """


class OAuthForm(forms.Form):
    """
    Form class that creates shallow error dicts and exists early when a
    :class:`OAuthValidationError` is raised.

    The shallow error dict is reused when returning error responses to the
    client.

    The different types of errors are outlined in :rfc:`4.2.2.1` and
    :rfc:`5.2`.
    """
    def __init__(self, *args, **kwargs):
        self.client = kwargs.pop('client', None)
        super(OAuthForm, self).__init__(*args, **kwargs)

    def _clean_fields(self):
        """
        Overriding the default cleaning behaviour to exit early on errors
        instead of validating each field.
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
