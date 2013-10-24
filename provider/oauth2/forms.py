from django import forms
from django.contrib.auth import authenticate
from django.utils.encoding import smart_unicode
from django.utils.translation import ugettext as _
from .. import scope
from ..constants import RESPONSE_TYPE_CHOICES, SCOPES
from ..forms import OAuthForm, OAuthValidationError
from ..scope import SCOPE_NAMES
from ..utils import now
from .models import Client, Grant, RefreshToken


class ClientForm(forms.ModelForm):
    """
    Form to create new consumers.
    """
    class Meta:
        model = Client
        fields = ('name', 'url', 'redirect_uri', 'client_type')

    def save(self, user=None, **kwargs):
        self.instance.user = user
        return super(ClientForm, self).save(**kwargs)


class ClientAuthForm(forms.Form):
    """
    Client authentication form. Required to make sure that we're dealing with a
    real client. Form is used in :attr:`provider.oauth2.backends` to validate
    the client.
    """
    client_id = forms.CharField()
    client_secret = forms.CharField()

    def clean(self):
        data = self.cleaned_data
        try:
            client = Client.objects.get(client_id=data.get('client_id'),
                client_secret=data.get('client_secret'))
        except Client.DoesNotExist:
            raise forms.ValidationError(_("Client could not be validated with "
                "key pair."))

        data['client'] = client
        return data


class ScopeChoiceField(forms.ChoiceField):
    """
    Custom form field that seperates values on space as defined in
    :rfc:`3.3`.
    """
    widget = forms.SelectMultiple

    def to_python(self, value):
        if not value:
            return []

        # New in Django 1.6: value may come in as a string.
        # Instead of raising an `OAuthValidationError`, try to parse and
        # ultimately return an empty list if nothing remains -- this will
        # eventually raise an `OAuthValidationError` in `validate` where
        # it should be anyways.
        if not isinstance(value, (list, tuple)):
            value = value.split(' ')

        # Split values into list
        return u' '.join([smart_unicode(val) for val in value]).split(u' ')

    def validate(self, value):
        """
        Validates that the input is a list or tuple.
        """
        if self.required and not value:
            raise OAuthValidationError({'error': 'invalid_request'})

        # Validate that each value in the value list is in self.choices.
        for val in value:
            if not self.valid_value(val):
                raise OAuthValidationError({
                    'error': 'invalid_request',
                    'error_description': _("'%s' is not a valid scope.") % \
                            val})


class ScopeMixin(object):
    """
    Form mixin to clean scope fields.
    """
    def clean_scope(self):
        """
        The scope is assembled by combining all the set flags into a single
        integer value which we can later check again for set bits.

        If *no* scope is set, we return the default scope which is the first
        defined scope in :attr:`provider.constants.SCOPES`.

        """
        default = SCOPES[0][0]

        flags = self.cleaned_data.get('scope', [])

        return scope.to_int(default=default, *flags)


class AuthorizationRequestForm(ScopeMixin, OAuthForm):
    """
    This form is used to validate the request data that the authorization
    endpoint receives from clients.

    Included data is specified in :rfc:`4.1.1`.
    """
    # Setting all required fields to false to explicitly check by hand
    # and use custom error messages that can be reused in the OAuth2
    # protocol
    response_type = forms.CharField(required=False)
    """
    ``"code"`` or ``"token"`` depending on the grant type.
    """

    redirect_uri = forms.URLField(required=False)
    """
    Where the client would like to redirect the user
    back to. This has to match whatever value was saved while creating
    the client.
    """

    state = forms.CharField(required=False)
    """
    Opaque - just pass back to the client for validation.
    """

    scope = ScopeChoiceField(choices=SCOPE_NAMES, required=False)
    """
    The scope that the authorization should include.
    """

    def clean_response_type(self):
        """
        :rfc:`3.1.1` Lists of values are space delimited.
        """
        response_type = self.cleaned_data.get('response_type')

        if not response_type:
            raise OAuthValidationError({'error': 'invalid_request',
                'error_description': "No 'response_type' supplied."})

        types = response_type.split(" ")

        for type in types:
            if type not in RESPONSE_TYPE_CHOICES:
                raise OAuthValidationError({
                    'error': 'unsupported_response_type',
                    'error_description': u"'%s' is not a supported response "
                        "type." % type})

        return response_type

    def clean_redirect_uri(self):
        """
        :rfc:`3.1.2` The redirect value has to match what was saved on the
            authorization server.
        """
        redirect_uri = self.cleaned_data.get('redirect_uri')

        if redirect_uri:
            if redirect_uri not in self.client.redirect_uri.split(" "):
                raise OAuthValidationError({
                    'error': 'invalid_request',
                    'error_description': _("The requested redirect didn't "
                        "match the client settings.")})

        return redirect_uri


class AuthorizationForm(ScopeMixin, OAuthForm):
    """
    A form used to ask the resource owner for authorization of a given client.
    """
    authorize = forms.BooleanField(required=False)
    scope = ScopeChoiceField(choices=SCOPE_NAMES, required=False)

    def save(self, **kwargs):
        authorize = self.cleaned_data.get('authorize')

        if not authorize:
            return None

        grant = Grant()
        grant.scope = self.cleaned_data.get('scope')
        return grant


class RefreshTokenGrantForm(ScopeMixin, OAuthForm):
    """
    Checks and returns a refresh token.
    """
    refresh_token = forms.CharField(required=False)
    scope = ScopeChoiceField(choices=SCOPE_NAMES, required=False)

    def clean_refresh_token(self):
        token = self.cleaned_data.get('refresh_token')

        if not token:
            raise OAuthValidationError({'error': 'invalid_request'})

        try:
            token = RefreshToken.objects.get(token=token,
                expired=False, client=self.client)
        except RefreshToken.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})

        return token

    def clean(self):
        """
        Make sure that the scope is less or equal to the previous scope!
        """
        data = self.cleaned_data
        want_scope = data.get('scope') or 0
        refresh_token = data.get('refresh_token')
        access_token = getattr(refresh_token, 'access_token', None) if \
            refresh_token else \
            None
        has_scope = access_token.scope if access_token else 0

        # Only check if we've actually got a scope in the data
        # (read: All fields have been cleaned)
        if want_scope is not 0 and not scope.check(want_scope, has_scope):
            raise OAuthValidationError({'error': 'invalid_scope'})

        return data


class AuthorizationCodeGrantForm(ScopeMixin, OAuthForm):
    """
    Check and return an authorization grant.
    """
    code = forms.CharField(required=False)
    scope = ScopeChoiceField(choices=SCOPE_NAMES, required=False)

    def clean_code(self):
        code = self.cleaned_data.get('code')

        if not code:
            raise OAuthValidationError({'error': 'invalid_request'})

        try:
            self.cleaned_data['grant'] = Grant.objects.get(
                code=code, client=self.client, expires__gt=now())
        except Grant.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})

        return code

    def clean(self):
        """
        Make sure that the scope is less or equal to the scope allowed on the
        grant!
        """
        data = self.cleaned_data
        want_scope = data.get('scope') or 0
        grant = data.get('grant')
        has_scope = grant.scope if grant else 0

        # Only check if we've actually got a scope in the data
        # (read: All fields have been cleaned)
        if want_scope is not 0 and not scope.check(want_scope, has_scope):
            raise OAuthValidationError({'error': 'invalid_scope'})

        return data


class PasswordGrantForm(ScopeMixin, OAuthForm):
    """
    Validate the password of a user on a password grant request.
    """
    username = forms.CharField(required=False)
    password = forms.CharField(required=False)
    scope = ScopeChoiceField(choices=SCOPE_NAMES, required=False)

    def clean_username(self):
        username = self.cleaned_data.get('username')

        if not username:
            raise OAuthValidationError({'error': 'invalid_request'})

        return username

    def clean_password(self):
        password = self.cleaned_data.get('password')

        if not password:
            raise OAuthValidationError({'error': 'invalid_request'})

        return password

    def clean(self):
        data = self.cleaned_data

        user = authenticate(username=data.get('username'),
            password=data.get('password'))

        if user is None:
            raise OAuthValidationError({'error': 'invalid_grant'})

        data['user'] = user
        return data


class PublicPasswordGrantForm(PasswordGrantForm):
    client_id = forms.CharField(required=True)
    grant_type = forms.CharField(required=True)

    def clean_grant_type(self):
        grant_type = self.cleaned_data.get('grant_type')

        if grant_type != 'password':
            raise OAuthValidationError({'error': 'invalid_grant'})

        return grant_type

    def clean(self):
        data = super(PublicPasswordGrantForm, self).clean()

        try:
            client = Client.objects.get(client_id=data.get('client_id'))
        except Client.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_client'})

        if client.client_type != 1: # public
            raise OAuthValidationError({'error': 'invalid_client'})

        data['client'] = client
        return data
