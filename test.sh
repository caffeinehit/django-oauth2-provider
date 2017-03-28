#!/bin/bash

DJ_VERSION=$(django-admin.py --version)

# exit if fail
[[ "$?" -ne "0" ]] && exit;

IS_16=$(echo $DJ_VERSION | grep -E "1\.6|1\.7|1\.8|dev")

app_names=( provider provider.oauth2 )

python manage.py test ${app_names[@]} --traceback --failfast
