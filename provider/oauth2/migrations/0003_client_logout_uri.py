# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0002_auto_20160404_0813'),
    ]

    operations = [
        migrations.AddField(
            model_name='client',
            name='logout_uri',
            field=models.URLField(help_text=b"Your application's logout URL", null=True, blank=True),
        ),
    ]
