#!/bin/bash

PYTHONPATH=$PWD/../:$PYTHONPATH

django-admin.py test provider oauth2 --settings tests.settings
