# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):

        # Changing field 'AccessToken.user'
        db.alter_column('oauth2_accesstoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True))

        # Changing field 'RefreshToken.user'
        db.alter_column('oauth2_refreshtoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True))

        # Changing field 'Grant.user'
        db.alter_column('oauth2_grant', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True))

    def backwards(self, orm):

        # User chose to not deal with backwards NULL issues for 'AccessToken.user'
        raise RuntimeError("Cannot reverse this migration. 'AccessToken.user' and its values cannot be restored.")
        
        # The following code is provided here to aid in writing a correct migration
        # Changing field 'AccessToken.user'
        db.alter_column('oauth2_accesstoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User']))

        # User chose to not deal with backwards NULL issues for 'RefreshToken.user'
        raise RuntimeError("Cannot reverse this migration. 'RefreshToken.user' and its values cannot be restored.")
        
        # The following code is provided here to aid in writing a correct migration
        # Changing field 'RefreshToken.user'
        db.alter_column('oauth2_refreshtoken', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User']))

        # User chose to not deal with backwards NULL issues for 'Grant.user'
        raise RuntimeError("Cannot reverse this migration. 'Grant.user' and its values cannot be restored.")
        
        # The following code is provided here to aid in writing a correct migration
        # Changing field 'Grant.user'
        db.alter_column('oauth2_grant', 'user_id', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User']))

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
        'auth.user': {
            'Meta': {'object_name': 'User'},
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
            'expires': ('django.db.models.fields.DateTimeField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'scope': ('django.db.models.fields.IntegerField', [], {'default': '2'}),
            'token': ('django.db.models.fields.CharField', [], {'default': "'24ade6505e92c283cbbee72c8f6faabe683c10b7'", 'max_length': '255', 'db_index': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'default': 'None', 'to': "orm['auth.User']", 'null': 'True'})
        },
        'oauth2.client': {
            'Meta': {'object_name': 'Client'},
            'client_id': ('django.db.models.fields.CharField', [], {'default': "'a598356133380ea98cde'", 'max_length': '255'}),
            'client_secret': ('django.db.models.fields.CharField', [], {'default': "'a4fecb78b026f17149aab0d636a1ab1103434a5d'", 'max_length': '255'}),
            'client_type': ('django.db.models.fields.IntegerField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'redirect_uri': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'url': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'oauth2_client'", 'null': 'True', 'to': "orm['auth.User']"})
        },
        'oauth2.grant': {
            'Meta': {'object_name': 'Grant'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.Client']"}),
            'code': ('django.db.models.fields.CharField', [], {'default': "'a0f847748e80a0726d5c2a94294c8944a591fd1c'", 'max_length': '255'}),
            'expires': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2014, 4, 28, 0, 0)'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'redirect_uri': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'scope': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'default': 'None', 'to': "orm['auth.User']", 'null': 'True'})
        },
        'oauth2.refreshtoken': {
            'Meta': {'object_name': 'RefreshToken'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'refresh_token'", 'unique': 'True', 'to': "orm['oauth2.AccessToken']"}),
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.Client']"}),
            'expired': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'default': "'be2cd71727dbbabdacecb9105018aaf59454d8aa'", 'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'default': 'None', 'to': "orm['auth.User']", 'null': 'True'})
        }
    }

    complete_apps = ['oauth2']