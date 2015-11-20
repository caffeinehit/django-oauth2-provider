#!/bin/bash

app_names=( provider provider.oauth2 )
coverage run --branch --source=provider manage.py test ${app_names[@]} --traceback --failfast
coverage report
