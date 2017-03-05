# -*- coding: utf-8 -*-
"""
    conftest
    ~~~~~~~~

    Test fixtures and what not
"""

import os
import tempfile
import time

import pytest

from flask import Flask, render_template
from flask_mail import Mail

from flask_security import Security, MongoEngineUserDatastore, SQLAlchemyUserDatastore, \
    PeeweeUserDatastore, UserMixin, RoleMixin, login_required, \
    roles_required, roles_accepted

from utils import populate_data, Response


@pytest.fixture()
def app(request):
    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config['SECRET_KEY'] = 'secret'
    app.config['TESTING'] = True
    app.config['LOGIN_DISABLED'] = False
    app.config['WTF_CSRF_ENABLED'] = False

    for opt in ['changeable', 'recoverable', 'registerable',
                'trackable', 'passwordless', 'confirmable']:
        app.config['SECURITY_' + opt.upper()] = opt in request.keywords

    if 'settings' in request.keywords:
        for key, value in request.keywords['settings'].kwargs.items():
            app.config['SECURITY_' + key.upper()] = value

    mail = Mail(app)
    app.mail = mail

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
    @login_required
    def http():
        return 'HTTP Authentication'

    @app.route('/token', methods=['GET', 'POST'])
    @login_required
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

    @app.route('/page1')
    def page_1():
        return 'Page 1'
    return app


@pytest.yield_fixture()
def mongoengine_datastore(request, app):
    from flask_mongoengine import MongoEngine

    db_name = 'flask_security_test_%s' % str(time.time()).replace('.', '_')
    app.config['MONGODB_SETTINGS'] = {
        'db': db_name,
        'host': 'localhost',
        'port': 27017,
        'alias': db_name
    }

    db = MongoEngine(app)

    class Role(db.Document, RoleMixin):
        name = db.StringField(required=True, unique=True, max_length=80)
        description = db.StringField(max_length=255)
        meta = {"db_alias": db_name}

    class User(db.Document, UserMixin):
        email = db.StringField(unique=True, max_length=255)
        username = db.StringField(max_length=255)
        password = db.StringField(required=False, max_length=255)
        last_login_at = db.DateTimeField()
        current_login_at = db.DateTimeField()
        last_login_ip = db.StringField(max_length=100)
        current_login_ip = db.StringField(max_length=100)
        login_count = db.IntField()
        active = db.BooleanField(default=True)
        confirmed_at = db.DateTimeField()
        roles = db.ListField(db.ReferenceField(Role), default=[])
        meta = {"db_alias": db_name}

    yield MongoEngineUserDatastore(db, User, Role)

    with app.app_context():
        db.connection.drop_database(db_name)


@pytest.fixture()
def sqlalchemy_datastore(request, app, tmpdir):
    from flask_sqlalchemy import SQLAlchemy

    f, path = tempfile.mkstemp(prefix='flask-security-test-db', suffix='.db', dir=str(tmpdir))

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path
    db = SQLAlchemy(app)

    roles_users = db.Table(
        'roles_users',
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

    with app.app_context():
        db.create_all()

    request.addfinalizer(lambda: os.remove(path))

    return SQLAlchemyUserDatastore(db, User, Role)


@pytest.fixture()
def peewee_datastore(request, app, tmpdir):
    from peewee import TextField, DateTimeField, IntegerField, BooleanField, ForeignKeyField
    from flask_peewee.db import Database

    f, path = tempfile.mkstemp(prefix='flask-security-test-db', suffix='.db', dir=str(tmpdir))

    app.config['DATABASE'] = {
        'name': path,
        'engine': 'peewee.SqliteDatabase'
    }

    db = Database(app)

    class Role(db.Model, RoleMixin):
        name = TextField(unique=True)
        description = TextField(null=True)

    class User(db.Model, UserMixin):
        email = TextField()
        username = TextField()
        password = TextField(null=True)
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

    with app.app_context():
        for Model in (Role, User, UserRoles):
            Model.create_table()

    request.addfinalizer(lambda: os.remove(path))

    return PeeweeUserDatastore(db, User, Role, UserRoles)


@pytest.fixture()
def sqlalchemy_app(app, sqlalchemy_datastore):
    def create():
        app.security = Security(app, datastore=sqlalchemy_datastore)
        return app
    return create


@pytest.fixture()
def peewee_app(app, peewee_datastore):
    def create():
        app.security = Security(app, datastore=peewee_datastore)
        return app
    return create


@pytest.fixture()
def mongoengine_app(app, mongoengine_datastore):
    def create():
        app.security = Security(app, datastore=mongoengine_datastore)
        return app
    return create


@pytest.fixture()
def client(request, sqlalchemy_app):
    app = sqlalchemy_app()
    populate_data(app)
    return app.test_client()


@pytest.fixture()
def get_message(app):
    def fn(key, **kwargs):
        rv = app.config['SECURITY_MSG_' + key][0] % kwargs
        return rv.encode('utf-8')
    return fn


@pytest.fixture(params=['sqlalchemy', 'mongoengine', 'peewee'])
def datastore(request, sqlalchemy_datastore, mongoengine_datastore, peewee_datastore):
    if request.param == 'sqlalchemy':
        rv = sqlalchemy_datastore
    elif request.param == 'mongoengine':
        rv = mongoengine_datastore
    elif request.param == 'peewee':
        rv = peewee_datastore
    return rv
