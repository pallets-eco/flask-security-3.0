# -*- coding: utf-8 -*-

import sys
import os

sys.path.pop(0)
sys.path.insert(0, os.getcwd())

from flask.ext.mongoengine import MongoEngine
from flask.ext.security import Security, UserMixin, RoleMixin, \
     MongoEngineUserDatastore

from tests.test_app import create_app as create_base_app, populate_data, \
     add_context_processors

def create_app(config, **kwargs):
    app = create_base_app(config)

    app.config['MONGODB_SETTINGS'] = dict(
        db='flask_security_test',
        host='localhost',
        port=27017
    )

    db = MongoEngine(app)

    class Role(db.Document, RoleMixin):
        name = db.StringField(required=True, unique=True, max_length=80)
        description = db.StringField(max_length=255)

    class User(db.Document, UserMixin):
        email = db.StringField(unique=True, max_length=255)
        password = db.StringField(required=True, max_length=255)
        last_login_at = db.DateTimeField()
        current_login_at = db.DateTimeField()
        last_login_ip = db.StringField(max_length=100)
        current_login_ip = db.StringField(max_length=100)
        login_count = db.IntField()
        active = db.BooleanField(default=True)
        confirmed_at = db.DateTimeField()
        roles = db.ListField(db.ReferenceField(Role), default=[])

    @app.before_first_request
    def before_first_request():
        User.drop_collection()
        Role.drop_collection()
        populate_data(app.config.get('USER_COUNT', None))

    app.security = Security(app, datastore=MongoEngineUserDatastore(db, User, Role), **kwargs)

    add_context_processors(app.security)

    return app

if __name__ == '__main__':
    create_app({}).run()
