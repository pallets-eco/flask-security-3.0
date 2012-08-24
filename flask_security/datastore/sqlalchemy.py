# -*- coding: utf-8 -*-
"""
    flask.ext.security.datastore.sqlalchemy
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This module contains a Flask-Security SQLAlchemy datastore implementation

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask.ext import security
from flask.ext.security import UserMixin, RoleMixin
from flask.ext.security.datastore import UserDatastore


class SQLAlchemyUserDatastore(UserDatastore):
    """A SQLAlchemy datastore implementation for Flask-Security.
    Example usage::

        from flask import Flask
        from flask.ext.security import Security
        from flask.ext.security.datastore.sqlalchemy import SQLAlchemyUserDatastore
        from flask.ext.sqlalchemy import SQLAlchemy

        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'secret'
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/flask_security_example.sqlite'

        db = SQLAlchemy(app)
        Security(app, SQLAlchemyUserDatastore(db))
    """

    def get_models(self):
        db = self.db
        user_account_mixin = self.user_account_mixin

        roles_users = db.Table('roles_users',
            db.Column('user_id', db.Integer(), db.ForeignKey('role.id')),
            db.Column('role_id', db.Integer(), db.ForeignKey('user.id')))

        class Role(db.Model, RoleMixin):
            """SQLAlchemy Role model"""

            id = db.Column(db.Integer(), primary_key=True)
            name = db.Column(db.String(80), unique=True)
            description = db.Column(db.String(255))

            def __init__(self, name=None, description=None):
                self.name = name
                self.description = description

        class User(db.Model, UserMixin, self.user_account_mixin):
            """SQLAlchemy User model"""

            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(255), unique=True)
            email = db.Column(db.String(255), unique=True)
            password = db.Column(db.String(120))
            active = db.Column(db.Boolean())
            created_at = db.Column(db.DateTime())
            modified_at = db.Column(db.DateTime())

            roles = db.relationship('Role', secondary=roles_users,
                                    backref=db.backref('users', lazy='dynamic'))

            def __init__(self, **kwargs):
                if not issubclass(user_account_mixin, object):
                    user_account_mixin.__init__(self, **kwargs)

                for field in ['username', 'email', 'password', 'created_at', 'modified_at']:
                    setattr(self, field, kwargs.get(field, None))

                self.active = kwargs.get('active', True)
                self.roles = kwargs.get('roles') or []

        return User, Role

    def _save_model(self, model):
        self.db.session.add(model)
        self.db.session.commit()
        return model

    def _do_with_id(self, id):
        return security.User.query.get(id)

    def _do_find_user(self, user):
        return security.User.query.filter_by(username=user).first() or \
               security.User.query.filter_by(email=user).first()

    def _do_find_role(self, role):
        return security.Role.query.filter_by(name=role).first()
