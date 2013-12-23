# -*- coding: utf-8 -*-

import sys
import os

sys.path.pop(0)
sys.path.insert(0, os.getcwd())

from flask_peewee.db import Database
from peewee import *
from flask.ext.security import Security, UserMixin, RoleMixin, \
     PeeweeUserDatastore

from tests.test_app import create_app as create_base_app, populate_data, \
     add_context_processors


def create_app(config, **kwargs):
    app = create_base_app(config)
    app.config['DATABASE'] = {
        'name': 'peewee.db',
        'engine': 'peewee.SqliteDatabase'
    }
    db = Database(app)

    class Role(db.Model, RoleMixin):
        name = TextField(unique=True)
        description = TextField(null=True)

    class User(db.Model, UserMixin):
        email = TextField()
        username = TextField()
        password = TextField()
        last_login_at = DateTimeField(null=True)
        current_login_at = DateTimeField(null=True)
        last_login_ip = TextField(null=True)
        current_login_ip = TextField(null=True)
        login_count = IntegerField(null=True)
        active = BooleanField(default=True)
        confirmed_at = DateTimeField(null=True)

    class UserRoles(db.Model):
        """ Peewee does not have built-in many-to-many support, so we have to
        create this mapping class to link users to roles."""
        user = ForeignKeyField(User, related_name='roles')
        role = ForeignKeyField(Role, related_name='users')
        name = property(lambda self: self.role.name)
        description = property(lambda self: self.role.description)

    @app.before_first_request
    def before_first_request():
        for Model in (Role, User, UserRoles):
            Model.drop_table(fail_silently=True)
            Model.create_table()
        populate_data(app.config.get('USER_COUNT', None))

    app.security = Security(app, datastore=PeeweeUserDatastore(db, User, Role, UserRoles), **kwargs)

    add_context_processors(app.security)

    return app

if __name__ == '__main__':
    create_app({}).run()
