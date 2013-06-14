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

To create a new entry simply use the Django admin panel.

Request an access token
-----------------------

Assuming that you've used the same URL configuration as above, your
client needs to submit a :attr:`POST` request to
:attr:`/oauth2/access_token` including the following parameters:

* ``client_id`` - The client ID you've configured in the Django admin.
* ``client_secret`` - The client secret configured in the Django admin.
* ``username`` - The username with which you want to log in.
* ``password`` - The password corresponding to the user you're logging
  in with.


**Request**

.. sourcecode:: sh 

    $ curl -X POST -d "client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&grant_type=password&username=YOUR_USERNAME&password=YOUR_PASSWORD" http://localhost:8000/oauth2/access_token/

**Response**

.. sourcecode:: json

    {"access_token": "<your-access-token>", "scope": "read", "expires_in": 86399, "refresh_token": "<your-refresh-token>"}


This particular way of obtaining an access token is called a **Password
Grant**. All the other ways of acquiring an access token are outlined
in :rfc:`4`.

.. note:: Remember that you should always use HTTPS for all your OAuth
	  2 requests otherwise you won't be secured. 



