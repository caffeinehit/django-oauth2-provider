try:
    from django.conf.urls import url, include
except ImportError: # django 1.3
    from django.conf.urls.defaults import patterns, url, include
