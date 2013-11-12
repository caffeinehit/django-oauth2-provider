# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models

from provider.compat import user_model_label


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding field 'AccessToken.created'
        db.add_column('oauth2_accesstoken', 'created',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now_add=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'AccessToken.modified'
        db.add_column('oauth2_accesstoken', 'modified',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'Client.created'
        db.add_column('oauth2_client', 'created',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now_add=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'Client.modified'
        db.add_column('oauth2_client', 'modified',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'RefreshToken.created'
        db.add_column('oauth2_refreshtoken', 'created',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now_add=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'RefreshToken.modified'
        db.add_column('oauth2_refreshtoken', 'modified',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'Grant.created'
        db.add_column('oauth2_grant', 'created',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now_add=True, null=True, blank=True),
                      keep_default=False)

        # Adding field 'Grant.modified'
        db.add_column('oauth2_grant', 'modified',
                      self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now=True, null=True, blank=True),
                      keep_default=False)


    def backwards(self, orm):
        # Deleting field 'AccessToken.created'
        db.delete_column('oauth2_accesstoken', 'created')

        # Deleting field 'AccessToken.modified'
        db.delete_column('oauth2_accesstoken', 'modified')

        # Deleting field 'Client.created'
        db.delete_column('oauth2_client', 'created')

        # Deleting field 'Client.modified'
        db.delete_column('oauth2_client', 'modified')

        # Deleting field 'RefreshToken.created'
        db.delete_column('oauth2_refreshtoken', 'created')

        # Deleting field 'RefreshToken.modified'
        db.delete_column('oauth2_refreshtoken', 'modified')

        # Deleting field 'Grant.created'
        db.delete_column('oauth2_grant', 'created')

        # Deleting field 'Grant.modified'
        db.delete_column('oauth2_grant', 'modified')


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
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now_add': 'True', 'null': 'True', 'blank': 'True'}),
            'expires': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2014, 1, 12, 0, 0)'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now': 'True', 'null': 'True', 'blank': 'True'}),
            'scope': ('django.db.models.fields.IntegerField', [], {'default': '2'}),
            'token': ('django.db.models.fields.CharField', [], {'default': "'78c91610e54cf3eae7158552d68f407c76c7b001'", 'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'oauth2.client': {
            'Meta': {'object_name': 'Client'},
            'client_id': ('django.db.models.fields.CharField', [], {'default': "'b9067d76f0f2c265ed4b'", 'max_length': '255'}),
            'client_secret': ('django.db.models.fields.CharField', [], {'default': "'9cafed6ab0bc5ca06a276475f8232f1beea6bef7'", 'max_length': '255'}),
            'client_type': ('django.db.models.fields.IntegerField', [], {}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now_add': 'True', 'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now': 'True', 'null': 'True', 'blank': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'redirect_uri': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'url': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'oauth2_client'", 'null': 'True', 'to': "orm['auth.User']"})
        },
        'oauth2.grant': {
            'Meta': {'object_name': 'Grant'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.Client']"}),
            'code': ('django.db.models.fields.CharField', [], {'default': "'e70adc880e03fc75d9fe3c3487237ad5a16aa146'", 'max_length': '255'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now_add': 'True', 'null': 'True', 'blank': 'True'}),
            'expires': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2013, 11, 13, 0, 0)'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now': 'True', 'null': 'True', 'blank': 'True'}),
            'redirect_uri': ('django.db.models.fields.CharField', [], {'max_length': '255', 'blank': 'True'}),
            'scope': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'oauth2.refreshtoken': {
            'Meta': {'object_name': 'RefreshToken'},
            'access_token': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'refresh_token'", 'unique': 'True', 'to': "orm['oauth2.AccessToken']"}),
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauth2.Client']"}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now_add': 'True', 'null': 'True', 'blank': 'True'}),
            'expired': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now': 'True', 'null': 'True', 'blank': 'True'}),
            'token': ('django.db.models.fields.CharField', [], {'default': "'f9798e71d48fee1252a18eed7bb27300966622c1'", 'max_length': '255'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        }
    }

    complete_apps = ['oauth2']