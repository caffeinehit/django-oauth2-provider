# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0003_client_logout_uri'),
    ]

    operations = [
        migrations.AlterIndexTogether(
            name='grant',
            index_together=set([('client', 'code', 'expires')]),
        ),
    ]
