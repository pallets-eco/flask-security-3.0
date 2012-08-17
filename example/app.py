# -*- coding: utf-8 -*-

# a little trick so you can run:
# $ python example/app.py
# from the root of the security project
import os
import sys
sys.path.pop(0)
sys.path.insert(0, os.getcwd())

from flask import Flask, render_template, current_app
from flask.ext.mail import Mail
from flask.ext.mongoengine import MongoEngine
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import Security, LoginForm, PasswordlessLoginForm, \
     login_required, roles_required, roles_accepted, UserMixin, RoleMixin
from flask.ext.security.datastore import SQLAlchemyUserDatastore, \
     MongoEngineUserDatastore
from flask.ext.security.decorators import http_auth_required, \
     auth_token_required
from flask.ext.security.exceptions import RoleNotFoundError


def create_roles():
    for role in ('admin', 'editor', 'author'):
        current_app.security.datastore.create_role(name=role)


def create_users():
    for u in  (('matt@lp.com', 'password', ['admin'], True),
               ('joe@lp.com', 'password', ['editor'], True),
               ('dave@lp.com', 'password', ['admin', 'editor'], True),
               ('jill@lp.com', 'password', ['author'], True),
               ('tiya@lp.com', 'password', [], False)):
        current_app.security.datastore.create_user(
            email=u[0], password=u[1], roles=u[2], active=u[3])


def populate_data():
    create_roles()
    create_users()


def add_ctx_processors(app):
    s = app.security

    @s.context_processor
    def for_all():
        return dict()

    @s.forgot_password_context_processor
    def forgot_password():
        return dict()

    @s.login_context_processor
    def login():
        return dict()

    @s.register_context_processor
    def register():
        return dict()

    @s.reset_password_context_processor
    def reset_password():
        return dict()

    @s.send_confirmation_context_processor
    def send_confirmation():
        return dict()

    @s.send_login_context_processor
    def send_login():
        return dict()


def create_app(auth_config):
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'secret'

    app.mail = Mail(app)

    if auth_config:
        for key, value in auth_config.items():
            app.config[key] = value

    @app.route('/')
    def index():
        return render_template('index.html', content='Home Page')

    @app.route('/profile')
    @login_required
    def profile():
        return render_template('index.html', content='Profile Page')

    @app.route('/post_login')
    @login_required
    def post_login():
        return render_template('index.html', content='Post Login')

    @app.route('/http')
    @http_auth_required
    def http():
        return render_template('index.html', content='HTTP Authentication')

    @app.route('/http_custom_realm')
    @http_auth_required('My Realm')
    def http_custom_realm():
        return render_template('index.html', content='HTTP Authentication')

    @app.route('/token')
    @auth_token_required
    def token():
        return render_template('index.html', content='Token Authentication')

    @app.route('/post_logout')
    def post_logout():
        return render_template('index.html', content='Post Logout')

    @app.route('/post_register')
    def post_register():
        return render_template('index.html', content='Post Register')

    @app.route('/admin')
    @roles_required('admin')
    def admin():
        return render_template('index.html', content='Admin Page')

    @app.route('/admin_and_editor')
    @roles_required('admin', 'editor')
    def admin_and_editor():
        return render_template('index.html', content='Admin and Editor Page')

    @app.route('/admin_or_editor')
    @roles_accepted('admin', 'editor')
    def admin_or_editor():
        return render_template('index.html', content='Admin or Editor Page')

    @app.route('/unauthorized')
    def unauthorized():
        return render_template('unauthorized.html')

    @app.route('/coverage/add_role_to_user')
    def add_role_to_user():
        ds = app.security.datastore
        u = ds.find_user(email='joe@lp.com')
        r = ds.find_role('admin')
        ds.add_role_to_user(u, r)
        return 'success'

    @app.route('/coverage/remove_role_from_user')
    def remove_role_from_user():
        ds = app.security.datastore
        u = ds.find_user(email='matt@lp.com')
        ds.remove_role_from_user(u, 'admin')
        return 'success'

    @app.route('/coverage/deactivate_user')
    def deactivate_user():
        ds = app.security.datastore
        u = ds.find_user(email='matt@lp.com')
        ds.deactivate_user(u)
        return 'success'

    @app.route('/coverage/activate_user')
    def activate_user():
        ds = app.security.datastore
        u = ds.find_user(email='tiya@lp.com')
        ds.activate_user(u)
        return 'success'

    @app.route('/coverage/invalid_role')
    def invalid_role():
        ds = app.security.datastore
        try:
            ds.find_role('bogus')
        except RoleNotFoundError:
            return 'success'

    return app


def create_sqlalchemy_app(auth_config=None, register_blueprint=True):
    app = create_app(auth_config)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/flask_security_test'

    db = SQLAlchemy(app)
    app.db = db

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

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role),
                            register_blueprint=register_blueprint)

    if not register_blueprint:
        from example import security
        blueprint = security.create_blueprint(app, 'flask_security', __name__)
        app.register_blueprint(blueprint)

    @app.before_first_request
    def before_first_request():
        db.drop_all()
        db.create_all()
        populate_data()

    add_ctx_processors(app)

    return app


def create_mongoengine_app(auth_config=None):
    app = create_app(auth_config)
    app.config['MONGODB_DB'] = 'flask_security_test'
    app.config['MONGODB_HOST'] = 'localhost'
    app.config['MONGODB_PORT'] = 27017

    db = MongoEngine(app)
    app.db = db

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

    app.security = Security(app, MongoEngineUserDatastore(db, User, Role))

    @app.before_first_request
    def before_first_request():
        User.drop_collection()
        Role.drop_collection()
        populate_data()

    add_ctx_processors(app)

    return app

if __name__ == '__main__':
    app = create_sqlalchemy_app()
    #app = create_mongoengine_app()
    app.run()
