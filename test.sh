#!/bin/bash

DJ_VERSION=$(django-admin.py --version)

# exit if fail
[[ "$?" -ne "0" ]] && exit;

IS_16=$(echo $DJ_VERSION | grep "1.6")

# if django version it's not 1.6 and so we pass different
# app names to test runner
if [ "$IS_16" = "1.6" ]; then
    app_names=( provider provider.oauth2 )
else
    app_names=( provider oauth2 )
fi

python manage.py test ${app_names[@]} --traceback --failfast
