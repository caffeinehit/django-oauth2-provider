from __future__ import unicode_literals

import time

from django.core.cache import cache

from . import constants


class Throttle(object):
    """
    Rate limit class based off of Django Rest Framework's SimpleRateThrottle
    https://github.com/tomchristie/django-rest-framework/blob/master/rest_framework/throttling.py#L53
    """
    def __init__(self):
        self.rate = constants.OAUTH2_THROTTLE_RATE
        self.num_requests, self.duration = self.parse_rate(self.rate)

    def get_ident(self, request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return ''.join(xff.split())
        return request.META.get('REMOTE_ADDR')

    def get_cache_key(self, request, view):
        return 'throttle_oauth2_{}'.format(self.get_ident(request))

    @staticmethod
    def parse_rate(rate):
        if rate is None:
            return (None, None)
        num, period = rate.split('/')
        num_requests = int(num)
        duration = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[period[0]]
        return (num_requests, duration)

    def allow_request(self, request, view):
        if self.rate is None:
            return True

        cache_key = self.get_cache_key(request, view)
        self.history = cache.get(cache_key, [])
        self.now = time.time()

        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()

        if len(self.history) >= self.num_requests:
            return False

        self.history.insert(0, self.now)
        cache.set(cache_key, self.history, self.duration)
        return True

    @property
    def wait(self):
        if self.history:
            remaining_duration = self.duration - (self.now - self.history[-1])
        else:
            remaining_duration = self.duration

        available_requests = self.num_requests - len(self.history) + 1
        if available_requests <= 0:
            return None

        return remaining_duration / float(available_requests)
