# -*- coding: utf-8 -*-
"""
    flask.ext.security.datastore
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This module contains an user datastore classes.

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app
from flask.ext.security import exceptions, confirmable


class UserDatastore(object):
    """Abstracted user datastore. Always extend this class and implement the
    :attr:`_save_model`, :attr:`_do_with_id`, :attr:`_do_find_user`,  and
    :attr:`_do_find_role` methods.

    :param db: An instance of a configured databse manager from a Flask
               extension such as Flask-SQLAlchemy or Flask-MongoEngine
    :param user_model: A user model class definition
    :param role_model: A role model class definition
    """
    def __init__(self, db, user_model, role_model):
        self.db = db
        self.user_model = user_model
        self.role_model = role_model

    def _save_model(self, model, **kwargs):
        raise NotImplementedError(
            "User datastore does not implement _save_model method")

    def _do_with_id(self, id):
        raise NotImplementedError(
            "User datastore does not implement _do_with_id method")

    def _do_find_user(self, **kwargs):
        raise NotImplementedError(
            "User datastore does not implement _do_find_user method")

    def _do_find_role(self, **kwargs):
        raise NotImplementedError(
            "User datastore does not implement _do_find_role method")

    def _prepare_create_role_args(self, kwargs):
        if kwargs['name'] is None:
            raise exceptions.RoleCreationError("Missing name argument")

        return kwargs

    def _prepare_create_user_args(self, kwargs):
        email = kwargs.get('email', None)
        password = kwargs.get('password', None)

        kwargs.setdefault('active', True)
        kwargs.setdefault('roles', current_app.security.default_roles)

        if current_app.security.confirm_email:
            confirmable.generate_confirmation_token(kwargs)

        if email is None:
            raise exceptions.UserCreationError('Missing email argument')

        if password is None:
            raise exceptions.UserCreationError('Missing password argument')

        roles = kwargs.get('roles', [])

        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, self.role_model) else role
            # see if the role exists
            roles[i] = self.find_role(rn)

        kwargs['roles'] = roles

        pwd_context = current_app.security.pwd_context
        pw = kwargs['password']
        if not pwd_context.identify(pw):
            kwargs['password'] = pwd_context.encrypt(pw)

        return kwargs

    def with_id(self, id):
        """Returns a user with the specified ID.

        :param id: User ID"""
        user = self._do_with_id(id)
        if user:
            return user
        raise exceptions.UserIdNotFoundError()

    def find_user(self, **kwargs):
        """Returns a user based on the specified identifier.

        :param user: User identifier, usually email address
        """
        user = self._do_find_user(**kwargs)
        if user:
            return user
        raise exceptions.UserNotFoundError('Parameters=%s' % kwargs)

    def find_role(self, role):
        """Returns a role based on its name.

        :param role: Role name
        """
        role = self._do_find_role(role)
        if role:
            return role
        raise exceptions.RoleNotFoundError()

    def create_role(self, **kwargs):
        """Creates and returns a new role.

        :param name: Role name
        """
        role = self.role_model(**self._prepare_create_role_args(kwargs))
        return self._save_model(role)

    def create_user(self, **kwargs):
        """Creates and returns a new user.

        :param email: Email address
        :param password: Unencrypted password
        :param active: The optional active state
        """
        user = self.user_model(**self._prepare_create_user_args(kwargs))
        return self._save_model(user)

    def add_role_to_user(self, user, role):
        """Adds a role to a user if the user does not have it already. Returns
        the modified user.

        :param user: A User instance or a user identifier
        :param role: A Role instance or a role name
        """
        return self._save_model(self._do_add_role(user, role))

    def remove_role_from_user(self, user, role, commit=True):
        """Removes a role from a user if the user has the role. Returns the
        modified user.

        :param user: A User instance or a user identifier
        :param role: A Role instance or a role name
        """
        return self._save_model(self._do_remove_role(user, role))

    def deactivate_user(self, user):
        """Deactivates a user and returns the modified user.

        :param user: A User instance or a user identifier
        """
        return self._save_model(self._do_deactive_user(user))

    def activate_user(self, user, commit=True):
        """Activates a user and returns the modified user.

        :param user: A User instance or a user identifier
        """
        return self._save_model(self._do_active_user(user))


class SQLAlchemyUserDatastore(UserDatastore):
    """A SQLAlchemy datastore implementation for Flask-Security.
    Example usage::

        from flask import Flask
        from flask.ext.security import Security, SQLAlchemyUserDatastore
        from flask.ext.sqlalchemy import SQLAlchemy

        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'secret'
        app.config['SQLALCHEMY_DATABASE_URI'] = \
            'sqlite:////tmp/flask_security_example.sqlite'

        db = SQLAlchemy(app)

        roles_users = db.Table('roles_users',
            db.Column('user_id', db.Integer(), db.ForeignKey('role.id')),
            db.Column('role_id', db.Integer(), db.ForeignKey('user.id')))

        class Role(db.Model, RoleMixin):
            id = db.Column(db.Integer(), primary_key=True)
            name = db.Column(db.String(80), unique=True)

        class User(db.Model, UserMixin):
            id = db.Column(db.Integer, primary_key=True)
            email = db.Column(db.String(255), unique=True)
            password = db.Column(db.String(120))
            first_name = db.Column(db.String(120))
            last_name = db.Column(db.String(120))
            active = db.Column(db.Boolean())
            created_at = db.Column(db.DateTime())
            modified_at = db.Column(db.DateTime())
            roles = db.relationship('Role', secondary=roles_users,
                backref=db.backref('users', lazy='dynamic'))

        Security(app, SQLAlchemyUserDatastore(db, User, Role))
    """

    def _save_model(self, model):
        self.db.session.add(model)
        self.db.session.commit()
        return model

    def _do_with_id(self, id):
        return self.user_model.query.get(id)

    def _do_find_user(self, **kwargs):
        return self.user_model.query.filter_by(**kwargs).first()

    def _do_find_role(self, role):
        return self.role_model.query.filter_by(name=role).first()


class MongoEngineUserDatastore(UserDatastore):
    """A MongoEngine datastore implementation for Flask-Security.
    Example usage::

        from flask import Flask
        from flask.ext.mongoengine import MongoEngine
        from flask.ext.security import Security, MongoEngineUserDatastore

        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'secret'
        app.config['MONGODB_DB'] = 'flask_security_example'
        app.config['MONGODB_HOST'] = 'localhost'
        app.config['MONGODB_PORT'] = 27017

        db = MongoEngine(app)

        class Role(db.Document, RoleMixin):
            name = db.StringField(required=True, unique=True, max_length=80)

        class User(db.Document, UserMixin):
            email = db.StringField(unique=True, max_length=255)
            password = db.StringField(required=True, max_length=120)
            active = db.BooleanField(default=True)
            roles = db.ListField(db.ReferenceField(Role), default=[])

        Security(app, MongoEngineUserDatastore(db, User, Role))
    """

    def _save_model(self, model):
        model.save()
        return model

    def _do_with_id(self, id):
        try:
            return self.user_model.objects.get(id=id)
        except:
            return None

    def _do_find_user(self, **kwargs):
        return self.user_model.objects(**kwargs).first()

    def _do_find_role(self, role):
        return self.role_model.objects(name=role).first()
