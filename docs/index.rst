Welcome to django-oauth2-provider's documentation!
==================================================

*django-oauth2-provider* is a Django application that provides customizable OAuth2_ authentication for your Django projects. 

The default implementation makes reasonable assumptions about the allowed  grant types and provides clients with two easy accessible URL endpoints. (:attr:`provider.oauth2.urls`)

If you require custom database backends, URLs, wish to extend the OAuth2_ protocol as defined in :rfc:`8` or anything else, you can override the default behaviours by subclassing the views in :attr:`provider.views` and add your specific use cases.

Getting started
###############

.. toctree::
   :maxdepth: 2

   getting_started

API
###

.. toctree::
   :maxdepth: 4
   
   api
   
Changes
#######

.. toctree::
    :maxdepth: 3
    
    changes


Made by `Caffeinehit <http://www.caffeinehit.com/>`_.

.. _OAuth2: http://tools.ietf.org/html/rfc6749
