# -*- coding: utf-8 -*-

import sys
import os

sys.path.pop(0)
sys.path.insert(0, os.getcwd())


from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import Security, UserMixin, RoleMixin, \
     SQLAlchemyUserDatastore

from tests.test_app import create_app as create_base_app, populate_data, \
     add_context_processors

def create_app(config, **kwargs):
    app = create_base_app(config)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    db = SQLAlchemy(app)

    roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

    class Role(db.Model, RoleMixin):
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(80), unique=True)
        description = db.Column(db.String(255))

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True)
        username = db.Column(db.String(255))
        password = db.Column(db.String(255))
        last_login_at = db.Column(db.DateTime())
        current_login_at = db.Column(db.DateTime())
        last_login_ip = db.Column(db.String(100))
        current_login_ip = db.Column(db.String(100))
        login_count = db.Column(db.Integer)
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship('Role', secondary=roles_users,
                                backref=db.backref('users', lazy='dynamic'))

    @app.before_first_request
    def before_first_request():
        db.drop_all()
        db.create_all()
        populate_data(app.config.get('USER_COUNT', None))

    app.security = Security(app, datastore=SQLAlchemyUserDatastore(db, User, Role), **kwargs)

    add_context_processors(app.security)

    return app

if __name__ == '__main__':
    create_app({}).run()
