from django.urls import path
from django.http.response import JsonResponse
from django.views.generic import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404

from provider.oauth2.mixins import OAuthRequiredMixin

app_name = 'tests'


class UserView(OAuthRequiredMixin, LoginRequiredMixin, View):
    accepted_oauth_scopes = ['read']

    def get(self, request, *args, **kwargs):
        user = get_object_or_404(User, pk=self.kwargs['pk'])
        return JsonResponse(
            {
                'username': user.username,
                'id': user.pk,
            }
        )


class BadScopeView(OAuthRequiredMixin, LoginRequiredMixin, View):
    accepted_oauth_scopes = ['badscope']

    def get(self, request, *args, **kwargs):
        user = self.request.user
        return JsonResponse(
            {
                'username': user.username,
                'id': user.pk,
            }
        )


urlpatterns = [
    path('badscope', BadScopeView.as_view(), name='badscope'),
    path('user/<int:pk>', UserView.as_view(), name='user'),
]
