#!/bin/bash

app_names=( provider provider.oauth2 )

python manage.py test ${app_names[@]} --traceback
