# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Deleting model 'Client'
        db.delete_table('oauth2_client')

        # Adding model 'BasicClient'
        db.create_table('oauth2_basicclient', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(blank=True, max_length=255)),
            ('url', self.gf('django.db.models.fields.URLField')(max_length=200)),
            ('redirect_uri', self.gf('django.db.models.fields.URLField')(max_length=200)),
            ('client_id', self.gf('django.db.models.fields.CharField')(max_length=255, default='295e481e6b023a87317c')),
            ('client_secret', self.gf('django.db.models.fields.CharField')(max_length=255, default='c6bb71793e0f5d904eee70ec20e08025ca448604')),
            ('client_type', self.gf('django.db.models.fields.IntegerField')()),
        ))
        db.send_create_signal('oauth2', ['BasicClient'])

        # Adding M2M table for field users on 'BasicClient'
        m2m_table_name = db.shorten_name('oauth2_basicclient_users')
        db.create_table(m2m_table_name, (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('basicclient', models.ForeignKey(orm['oauth2.basicclient'], null=False)),
            ('user', models.ForeignKey(orm['auth.user'], null=False))
        ))
        db.create_unique(m2m_table_name, ['basicclient_id', 'user_id'])


        # Changing field 'AccessToken.client'
        db.alter_column('oauth2_accesstoken', 'client_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauth2.BasicClient']))

        # Changing field 'Grant.client'
        db.alter_column('oauth2_grant', 'client_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauth2.BasicClient']))

        # Changing field 'RefreshToken.client'
        db.alter_column('oauth2_refreshtoken', 'client_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauth2.BasicClient']))

    def backwards(self, orm):
        # Adding model 'Client'
        db.create_table('oauth2_client', (
            ('client_type', self.gf('django.db.models.fields.IntegerField')()),
            ('client_secret', self.gf('django.db.models.fields.CharField')(max_length=255, default='e53ddb9736f9eea65100885a1b20fb5f2bb0fb4d')),
            ('redirect_uri', self.gf('django.db.models.fields.URLField')(max_length=200)),
            ('url', self.gf('django.db.models.fields.URLField')(max_length=200)),
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(blank=True, to=orm['auth.User'], related_name='oauth2_client', null=True)),
            ('name', self.gf('django.db.models.fields.CharField')(blank=True, max_length=255)),
            ('client_id', self.gf('django.db.models.fields.CharField')(max_length=255, default='0a8e54e38c024606ba0a')),
        ))
        db.send_create_signal('oauth2', ['Client'])

        # Deleting model 'BasicClient'
        db.delete_table('oauth2_basicclient')

        # Removing M2M table for field users on 'BasicClient'
        db.delete_table(db.shorten_name('oauth2_basicclient_users'))


        # Changing field 'AccessToken.client'
        db.alter_column('oauth2_accesstoken', 'client_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauth2.Client']))

        # Changing field 'Grant.client'
        db.alter_column('oauth2_grant', 'client_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauth2.Client']))

        # Changing field 'RefreshToken.client'
        db.alter_column('oauth2_refreshtoken', 'client_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauth2.Client']))

    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '80', 'unique': 'True'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'blank': 'True', 'symmetrical': 'False'})
        },
        'auth.permission': {
            'Meta': {'ordering': "('content_type__app_label', 'content_type__model', 'codename')", 'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'blank': 'True', 'max_length': '75'}),
            'first_name': ('django.db.models.fields.CharField', [], {'blank': 'True', 'max_length': '30'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Group']", 'blank': 'True', 'symmetrical': 'False', 'related_name': "'user_set'"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'blank': 'True', 'max_length': '30'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'blank': 'True', 'symmetrical': 'False', 'related_name': "'user_set'"}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '30', 'unique': 'True'})
        },
        'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'db_table': "'django_content_type'", 'object_name': 'ContentType'},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'oauth2.accesstoken': {
            'Meta': {'object_name': 'AccessToken'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.BasicClient']"}),
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'scope': ('django.db.models.fields.IntegerField', [], {'default': '2'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255', 'default': "'a64675c488a638f06e14f415598aa46869388154'", 'db_index': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'oauth2.basicclient': {
            'Meta': {'object_name': 'BasicClient'},
            'client_id': ('django.db.models.fields.CharField', [], {'max_length': '255', 'default': "'46131deb8844b09c26fd'"}),
            'client_secret': ('django.db.models.fields.CharField', [], {'max_length': '255', 'default': "'f0a631177e970f780849150b282a1f89177bcd94'"}),
            'client_type': ('django.db.models.fields.IntegerField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'blank': 'True', 'max_length': '255'}),
            'redirect_uri': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'url': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'users': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.User']", 'blank': 'True', 'symmetrical': 'False', 'related_name': "'oauth2_clients'", 'null': 'True'})
        },
        'oauth2.grant': {
            'Meta': {'object_name': 'Grant'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.BasicClient']"}),
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255', 'default': "'d732cfddf119edbb7cb2ed8e1e8f6a885b96380e'"}),
            'expires': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2014, 1, 24, 0, 0)'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'redirect_uri': ('django.db.models.fields.CharField', [], {'blank': 'True', 'max_length': '255'}),
            'scope': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'oauth2.refreshtoken': {
            'Meta': {'object_name': 'RefreshToken'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'to': "orm['oauth2.AccessToken']", 'related_name': "'refresh_token'", 'unique': 'True'}),
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.BasicClient']"}),
            'expired': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'max_length': '255', 'default': "'8783c40888955c1f879fbd33e6d1fcf73705a109'"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        }
    }

    complete_apps = ['oauth2']
