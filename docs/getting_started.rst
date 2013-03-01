Getting started
===============

Installation
############

.. sourcecode:: sh

    $ pip install django-oauth2-provider

Configuration
#############

Add OAuth2 Provider to :attr:`INSTALLED_APPS`
---------------------------------------------

::

    INSTALLED_APPS = (
        # ...
        'provider',
        'provider.oauth2',
    )       

Modify your settings to match your needs
----------------------------------------

The default settings are available in :attr:`provider.constants`.


Include the OAuth 2 views
-------------------------

Add :attr:`provider.oauth2.urls` to your root ``urls.py`` file. 

::

    url(r'^oauth2/', include('provider.oauth2.urls', namespace = 'oauth2')),
    
    
.. note:: The namespace argument is required.    

Sync your database
------------------

.. sourcecode:: sh

    $ python manage.py syncdb
    $ python manage.py migrate

How to request an :attr:`access token` for the first time ?
###########################################################

Create a :attr:`client` entry in your database
----------------------------------------------

.. note:: To find out which type of :attr:`client` you need to create, read :rfc:`2.1`.

To create a new entry, simply use the django admin panel.

Request an access token
-----------------------

Your client interface – I mean by that your iOS code, HTML code, or whatever else language – just have to submit a :attr:`POST` request at the url :attr:`/oauth2/access_token` with the following fields :

* client_id the client id you've just configured at the previous step.
* client_secret again configured at the previous step.
* username the username with which you want to log in.
* password well, that speaks for itself.

This is only one way to authenticate with OAuth 2, there is other methods but I will only show you the :attr:`PasswordGrant` type one in this quick "Getting started" guide.

.. note:: Remember that you SHOULD always use HTTPS for all your OAuth 2 requests otherwise you won't be secured.

Now you can use the command line to check that your local configuration is working : 

.. sourcecode:: sh 

    $ curl -X POST -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&grant_type=password&username=YOUR_USERNAME&password=YOUR_PASSWORD" http://localhost:8000/oauth2/access_token/

Here is the response you should get :

.. sourcecode:: json

    {"access_token": "<your-access-token>", "scope": "read", "expires_in": 86399, "refresh_token": "<your-refresh-token>"}