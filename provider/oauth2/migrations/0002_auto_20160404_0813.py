# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accesstoken',
            name='user',
            field=models.ForeignKey(related_name='dop_access_token', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='grant',
            name='user',
            field=models.ForeignKey(related_name='dop_grant', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='refreshtoken',
            name='user',
            field=models.ForeignKey(related_name='dop_refresh_token', to=settings.AUTH_USER_MODEL),
        ),
    ]
