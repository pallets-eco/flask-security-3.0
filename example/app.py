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
from flask.ext.security import Security, LoginForm, login_required, \
     roles_required, roles_accepted, UserMixin, RoleMixin
from flask.ext.security.datastore import SQLAlchemyUserDatastore, \
     MongoEngineUserDatastore
from flask.ext.security.decorators import http_auth_required, \
     auth_token_required


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
            email=u[0], password=u[1], roles=u[2], active=u[3],
            authentication_token='123abc')


def populate_data():
    create_roles()
    create_users()


def create_app(auth_config):
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'secret'

    if auth_config:
        for key, value in auth_config.items():
            app.config[key] = value

    app.mail = Mail(app)

    @app.route('/')
    def index():
        return render_template('index.html', content='Home Page')

    @app.route('/login')
    def login():
        return render_template('login.html', content='Login Page', form=LoginForm())

    @app.route('/custom_login')
    def custom_login():
        return render_template('login.html', content='Custom Login Page', form=LoginForm())

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

    return app


def create_sqlalchemy_app(auth_config=None):
    app = create_app(auth_config)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/flask_security_test'

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
        password = db.Column(db.String(120))
        remember_token = db.Column(db.String(255))
        last_login_at = db.Column(db.DateTime())
        current_login_at = db.Column(db.DateTime())
        last_login_ip = db.Column(db.String(100))
        current_login_ip = db.Column(db.String(100))
        login_count = db.Column(db.Integer)
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        authentication_token = db.Column(db.String(255))
        roles = db.relationship('Role', secondary=roles_users,
                                backref=db.backref('users', lazy='dynamic'))

    Security(app, SQLAlchemyUserDatastore(db, User, Role))

    @app.before_first_request
    def before_first_request():
        db.drop_all()
        db.create_all()
        populate_data()

    return app


def create_mongoengine_app(auth_config=None):
    app = create_app(auth_config)
    app.config['MONGODB_DB'] = 'flask_security_test'
    app.config['MONGODB_HOST'] = 'localhost'
    app.config['MONGODB_PORT'] = 27017

    db = MongoEngine(app)

    class Role(db.Document, RoleMixin):
        name = db.StringField(required=True, unique=True, max_length=80)
        description = db.StringField(max_length=255)

    class User(db.Document, UserMixin):
        email = db.StringField(unique=True, max_length=255)
        password = db.StringField(required=True, max_length=120)
        remember_token = db.StringField(max_length=255)
        last_login_at = db.DateTimeField()
        current_login_at = db.DateTimeField()
        last_login_ip = db.StringField(max_length=100)
        current_login_ip = db.StringField(max_length=100)
        login_count = db.IntField()
        active = db.BooleanField(default=True)
        confirmed_at = db.DateTimeField()
        authentication_token = db.StringField(max_length=255)
        roles = db.ListField(db.ReferenceField(Role), default=[])

    Security(app, MongoEngineUserDatastore(db, User, Role))

    @app.before_first_request
    def before_first_request():
        User.drop_collection()
        Role.drop_collection()
        populate_data()

    return app

if __name__ == '__main__':
    app = create_sqlalchemy_app()
    #app = create_mongoengine_app()
    app.run()
