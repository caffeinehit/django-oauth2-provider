from django.utils.decorators import classonlymethod
from django.http.response import JsonResponse


class OAuthRegisteredScopes(object):
    scopes = set()


class OAuthRequiredMixin(object):
    accepted_oauth_scopes = []

    @classonlymethod
    def as_view(cls, *args, **kwargs):
        for scope in cls.accepted_oauth_scopes:
            OAuthRegisteredScopes.scopes.add(scope)

        return super(OAuthRequiredMixin, cls).as_view()

    def dispatch(self, request, *args, **kwargs):
        scopes = list()
        if hasattr(request, 'oauth2_token'):
            scopes = set(request.oauth2_token.scope.all().values_list('name', flat=True))

            if request.user.is_authenticated and scopes.intersection(self.accepted_oauth_scopes):
                return super(OAuthRequiredMixin, self).dispatch(request, *args, **kwargs)

        return JsonResponse(
            {
                'error': 'bad_access_token',
                'accepted_scopes': sorted(self.accepted_oauth_scopes),
                'token_scopes': sorted(scopes)
            },
            status=401
        )
