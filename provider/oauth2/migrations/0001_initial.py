# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import provider.utils
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AccessToken',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('token', models.CharField(default=provider.utils.long_token, max_length=255, db_index=True)),
                ('expires', models.DateTimeField()),
            ],
            options={
                'db_table': 'oauth2_accesstoken',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='AuthorizedClient',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('authorized_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'oauth2_authorizedclient',
            },
            bases=(models.Model,),
        ),
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
                ('auto_authorize', models.BooleanField(default=False)),
                ('user', models.ForeignKey(related_name='oauth2_client', blank=True, to=settings.AUTH_USER_MODEL, null=True, on_delete=models.DO_NOTHING)),
            ],
            options={
                'db_table': 'oauth2_client',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Grant',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('code', models.CharField(default=provider.utils.long_token, max_length=255)),
                ('expires', models.DateTimeField(default=provider.utils.get_code_expiry)),
                ('redirect_uri', models.CharField(max_length=255, blank=True)),
                ('client', models.ForeignKey(to='oauth2.Client', on_delete=models.DO_NOTHING)),
            ],
            options={
                'db_table': 'oauth2_grant',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='RefreshToken',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('token', models.CharField(default=provider.utils.long_token, max_length=255)),
                ('expired', models.BooleanField(default=False)),
                ('access_token', models.OneToOneField(related_name='refresh_token', to='oauth2.AccessToken', on_delete=models.DO_NOTHING)),
                ('client', models.ForeignKey(to='oauth2.Client', on_delete=models.DO_NOTHING)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING)),
            ],
            options={
                'db_table': 'oauth2_refreshtoken',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Scope',
            fields=[
                ('name', models.CharField(max_length=15, serialize=False, primary_key=True)),
                ('description', models.CharField(default=b'', max_length=256, blank=True)),
            ],
            options={
                'db_table': 'oauth2_scope',
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='grant',
            name='scope',
            field=models.ManyToManyField(to='oauth2.Scope'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='grant',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='authorizedclient',
            name='client',
            field=models.ForeignKey(to='oauth2.Client', on_delete=models.DO_NOTHING),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='authorizedclient',
            name='scope',
            field=models.ManyToManyField(to='oauth2.Scope'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='authorizedclient',
            name='user',
            field=models.ForeignKey(related_name='oauth2_authorized_client', to=settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='authorizedclient',
            unique_together=set([('user', 'client')]),
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='client',
            field=models.ForeignKey(to='oauth2.Client', on_delete=models.DO_NOTHING),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='scope',
            field=models.ManyToManyField(to='oauth2.Scope'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING),
            preserve_default=True,
        ),
        migrations.RunSQL("INSERT INTO oauth2_scope (name, description) values ('read', 'Read-Only access') "),
        ]
