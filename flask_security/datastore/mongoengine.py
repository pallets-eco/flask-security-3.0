# -*- coding: utf-8 -*-
"""
    flask.ext.security.datastore.mongoengine
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This module contains a Flask-Security MongoEngine datastore implementation

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask.ext import security
from flask.ext.security import UserMixin, RoleMixin
from flask.ext.security.datastore import UserDatastore
    
class MongoEngineUserDatastore(UserDatastore):
    """A MongoEngine datastore implementation for Flask-Security. Example: 
    
        from flask import Flask
        from flask.ext.mongoengine import MongoEngine
        from flask.ext.security import Security
        from flask.ext.security.datastore.mongoengine import MongoEngineUserDatastore
        
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'secret'
        app.config['MONGODB_DB'] = 'flask_security_example'
        app.config['MONGODB_HOST'] = 'localhost'
        app.config['MONGODB_PORT'] = 27017
    
        db = MongoEngine(app)
        Security(app, MongoEngineUserDatastore(db))
    """
    
    def get_models(self):
        db = self.db
        
        class Role(db.Document, RoleMixin):
            """MongoEngine Role model"""
            
            name = db.StringField(required=True, unique=True, max_length=80)
            description = db.StringField(max_length=255)
              
        class User(db.Document, UserMixin):
            """MongoEngine User model"""
            
            username = db.StringField(unique=True, max_length=255)
            email = db.StringField(unique=True, max_length=255)
            password = db.StringField(required=True, max_length=120)
            active = db.BooleanField(default=True)
            roles= db.ListField(db.ReferenceField(Role), default=[])
            created_at = db.DateTimeField()
            modified_at = db.DateTimeField()
            
        return User, Role
    
    def _save_model(self, model):
        model.save()
        return model
        
    def _do_with_id(self, id):
        try: return security.User.objects.get(id=id)
        except: return None
    
    def _do_find_user(self, user):
        return security.User.objects(username=user).first() or \
               security.User.objects(email=user).first()
    
    def _do_find_role(self, role):
        return security.Role.objects(name=role).first()
    