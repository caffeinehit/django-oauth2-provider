Welcome to django-oauth2-provider's documentation!
==================================================

*django-oauth2-provider* is a Django application that provides customizable OAuth2_ authentication for your Django projects. 

The default implementation makes reasonable assumptions about the allowed  grant types and provides clients with two easy accessible URL endpoints. (:attr:`provider.oauth2.urls`)

If you require custom database backends, URLs, wish to extend the OAuth2_ protocol as defined in :draft:`8` or anything else, you can override the default behaviours by subclassing the views in :attr:`provider.views` and add your specific use cases.

Installation
############

::

    pip install django-oauth2-provider
    

Configuration
#############

An example configuration is included in the repository_.

If you're happy using the default backend add these two lines to your settings:

::

    INSTALLED_APPS = (
        # ...
        'provider',
        'provider.oauth2',
    )       

And include :attr:`provider.oauth2.urls` into your root ``urls.py`` file. 

::

    url(r'^oauth2/', include('provider.oauth2.urls', namespace = 'oauth2')),
    
    
.. note:: The namespace argument is required.    


Settings
########

The default settings are available in :attr:`provider.constants`.


.. toctree::
   :maxdepth: 4
   
   api


Made by `Caffeinehit <http://www.caffeinehit.com/>`_.

.. _OAuth2: http://tools.ietf.org/html/draft-ietf-oauth-v2-23
.. _repository: https://github.com/caffeinehit/django-oauth2-provider/blob/master/example/settings.py