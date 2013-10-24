# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models

from provider.compat import user_model_label


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Changing field 'Client.redirect_uri'
        db.alter_column('oauth2_client', 'redirect_uri', self.gf('django.db.models.fields.TextField')())

    def backwards(self, orm):
        # Changing field 'Client.redirect_uri'
        db.alter_column('oauth2_client', 'redirect_uri', self.gf('django.db.models.fields.URLField')(max_length=200))

    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        'auth.permission': {
            'Meta': {'ordering': "('content_type__app_label', 'content_type__model', 'codename')", 'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        user_model_label: {
            'Meta': {'object_name': user_model_label.split('.')[-1]},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'oauth2.accesstoken': {
            'Meta': {'object_name': 'AccessToken'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.Client']"}),
            'expires': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2014, 1, 12, 0, 0)'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'scope': ('django.db.models.fields.IntegerField', [], {'default': '2'}),
            'token': ('django.db.models.fields.CharField', [], {'default': "'87c85bc889d7541395f63f1c8244818dc80f6e00'", 'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'oauth2.client': {
            'Meta': {'object_name': 'Client'},
            'client_id': ('django.db.models.fields.CharField', [], {'default': "'8c5aaa32c25f94cb8d93'", 'max_length': '255'}),
            'client_secret': ('django.db.models.fields.CharField', [], {'default': "'ee822b8b3ce8f2228e2d73d2bd923fc95cae00fd'", 'max_length': '255'}),
            'client_type': ('django.db.models.fields.IntegerField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'redirect_uri': ('django.db.models.fields.TextField', [], {}),
            'url': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'oauth2_client'", 'null': 'True', 'to': "orm['auth.User']"})
        },
        'oauth2.grant': {
            'Meta': {'object_name': 'Grant'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.Client']"}),
            'code': ('django.db.models.fields.CharField', [], {'default': "'8918930615a81c12fc19496d6abfbb75723e6848'", 'max_length': '255'}),
            'expires': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2013, 11, 13, 0, 0)'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'redirect_uri': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'scope': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'oauth2.refreshtoken': {
            'Meta': {'object_name': 'RefreshToken'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'refresh_token'", 'unique': 'True', 'to': "orm['oauth2.AccessToken']"}),
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.Client']"}),
            'expired': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'default': "'b20035ed4485dcdae8887100ed991ab1fcf004de'", 'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        }
    }

    complete_apps = ['oauth2']