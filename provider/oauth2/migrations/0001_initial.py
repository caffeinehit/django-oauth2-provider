# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import provider.utils


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=255, blank=True)),
                ('url', models.URLField(help_text=b"Your application's URL.")),
                ('redirect_uri', models.URLField(help_text=b"Your application's callback URL")),
                ('client_id', models.CharField(default=provider.utils.short_token, max_length=255)),
                ('client_secret', models.CharField(default=provider.utils.long_token, max_length=255)),
                ('client_type', models.IntegerField(choices=[(0, b'Confidential (Web applications)'), (1, b'Public (Native and JS applications)')])),
                ('user', models.ForeignKey(related_name='oauth2_client', blank=True, to=settings.AUTH_USER_MODEL, null=True)),
            ],
        ),
    ]
