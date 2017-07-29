# -*- coding: utf-8 -*-
"""
    conftest
    ~~~~~~~~

    Test fixtures and what not

    :copyright: (c) 2017 by CERN.
    :license: MIT, see LICENSE for more details.
"""

import os
import tempfile
import time
from datetime import datetime

import pytest
from flask import Flask, render_template
from flask.json import JSONEncoder as BaseEncoder
from flask_babelex import Babel
from flask_mail import Mail
from speaklater import is_lazy_string
from utils import Response, populate_data

from flask_security import MongoEngineUserDatastore, PeeweeUserDatastore, \
    PonyUserDatastore, RoleMixin, Security, SQLAlchemySessionUserDatastore, \
    SQLAlchemyUserDatastore, UserMixin, auth_required, auth_token_required, \
    http_auth_required, login_required, roles_accepted, roles_required


class JSONEncoder(BaseEncoder):

    def default(self, o):
        if is_lazy_string(o):
            return str(o)

        return BaseEncoder.default(self, o)


def create_fixture_app(keywords, identity_attrs):
    app = Flask(__name__)
    app.response_class = Response
    app.debug = True
    app.config['SECRET_KEY'] = 'secret'
    app.config['TESTING'] = True
    app.config['LOGIN_DISABLED'] = False
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] = identity_attrs

    app.config['SECURITY_PASSWORD_SALT'] = 'salty'

    for opt in ['changeable', 'recoverable', 'registerable',
                'trackable', 'passwordless', 'confirmable']:
        app.config['SECURITY_' + opt.upper()] = opt in keywords

    if 'settings' in keywords:
        for key, value in keywords['settings'].kwargs.items():
            app.config['SECURITY_' + key.upper()] = value

    mail = Mail(app)
    if 'babel' not in keywords or keywords['babel'].args[0]:
        babel = Babel(app)
        app.babel = babel
    app.json_encoder = JSONEncoder
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
    @http_auth_required
    def http():
        return 'HTTP Authentication'

    @app.route('/http_custom_realm')
    @http_auth_required('My Realm')
    def http_custom_realm():
        return render_template('index.html', content='HTTP Authentication')

    @app.route('/token', methods=['GET', 'POST'])
    @auth_token_required
    def token():
        return render_template('index.html', content='Token Authentication')

    @app.route('/multi_auth')
    @auth_required('session', 'token', 'basic')
    def multi_auth():
        return render_template(
            'index.html',
            content='Session, Token, Basic auth')

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


@pytest.fixture()
def username_app(request):
    return create_fixture_app(request.keywords, ["username"])


@pytest.fixture()
def email_app(request):
    return create_fixture_app(request.keywords, ["email"])


@pytest.fixture()
def app(email_app):  # , username_app):
    # TODO: this fixture should be parametrized, like the `datastore` fixture
    return email_app


@pytest.yield_fixture()
def mongoengine_email_datastore(email_app):
    from flask_mongoengine import MongoEngine

    db_name = 'flask_security_test_%s' % str(time.time()).replace('.', '_')
    email_app.config['MONGODB_SETTINGS'] = {
        'db': db_name,
        'host': 'localhost',
        'port': 27017,
        'alias': db_name
    }

    db = MongoEngine(email_app)

    class Role(db.Document, RoleMixin):
        name = db.StringField(required=True, unique=True, max_length=80)
        description = db.StringField(max_length=255)
        meta = {"db_alias": db_name}

    class User(db.Document, UserMixin):
        email = db.StringField(unique=True, max_length=255)
        username = db.StringField(max_length=255)  # TODO: remove
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

    with email_app.app_context():
        db.connection.drop_database(db_name)


@pytest.yield_fixture()
def mongoengine_username_datastore(username_app):
    from flask_mongoengine import MongoEngine

    db_name = 'flask_security_test_%s' % str(time.time()).replace('.', '_')
    username_app.config['MONGODB_SETTINGS'] = {
        'db': db_name,
        'host': 'localhost',
        'port': 27017,
        'alias': db_name
    }

    db = MongoEngine(username_app)

    class Role(db.Document, RoleMixin):
        name = db.StringField(required=True, unique=True, max_length=80)
        description = db.StringField(max_length=255)
        meta = {"db_alias": db_name}

    class User(db.Document, UserMixin):
        username = db.StringField(unique=True, max_length=255)
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

    with username_app.app_context():
        db.connection.drop_database(db_name)


@pytest.fixture()
def mongoengine_datastore(app,
                          mongoengine_email_datastore,
                          mongoengine_username_datastore):
    if app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] == ["email"]:
        return mongoengine_email_datastore
    else:
        return mongoengine_username_datastore


@pytest.fixture()
def sqlalchemy_email_datastore(request, email_app, tmpdir):
    from flask_sqlalchemy import SQLAlchemy

    f, path = tempfile.mkstemp(
        prefix='flask-security-test-db', suffix='.db', dir=str(tmpdir))

    email_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path
    db = SQLAlchemy(email_app)

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
        username = db.Column(db.String(255))  # TODO: remove
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

    with email_app.app_context():
        db.create_all()

    def tear_down():
        os.close(f)
        os.remove(path)
    request.addfinalizer(tear_down)

    return SQLAlchemyUserDatastore(db, User, Role)


@pytest.fixture()
def sqlalchemy_username_datastore(request, username_app, tmpdir):
    from flask_sqlalchemy import SQLAlchemy

    f, path = tempfile.mkstemp(
        prefix='flask-security-test-db', suffix='.db', dir=str(tmpdir))

    username_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path
    db = SQLAlchemy(username_app)

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
        username = db.Column(db.String(255), unique=True)
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

    with username_app.app_context():
        db.create_all()

    def tear_down():
        os.close(f)
        os.remove(path)
    request.addfinalizer(tear_down)

    return SQLAlchemyUserDatastore(db, User, Role)


@pytest.fixture()
def sqlalchemy_datastore(app,
                         sqlalchemy_email_datastore,
                         sqlalchemy_username_datastore):
    if app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] == ["email"]:
        return sqlalchemy_email_datastore
    else:
        return sqlalchemy_username_datastore


@pytest.fixture()
def sqlalchemy_session_email_datastore(request, email_app, tmpdir):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker, relationship, \
        backref
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Boolean, DateTime, Column, Integer, String, \
        ForeignKey

    f, path = tempfile.mkstemp(
        prefix='flask-security-test-db', suffix='.db', dir=str(tmpdir))

    email_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path

    engine = create_engine(email_app.config['SQLALCHEMY_DATABASE_URI'],
                           convert_unicode=True)
    db_session = scoped_session(sessionmaker(autocommit=False,
                                             autoflush=False,
                                             bind=engine))
    Base = declarative_base()
    Base.query = db_session.query_property()

    class RolesUsers(Base):
        __tablename__ = 'roles_users'
        id = Column(Integer(), primary_key=True)
        user_id = Column('user_id', Integer(), ForeignKey('user.id'))
        role_id = Column('role_id', Integer(), ForeignKey('role.id'))

    class Role(Base, RoleMixin):
        __tablename__ = 'role'
        id = Column(Integer(), primary_key=True)
        name = Column(String(80), unique=True)
        description = Column(String(255))

    class User(Base, UserMixin):
        __tablename__ = 'user'
        id = Column(Integer, primary_key=True)
        email = Column(String(255), unique=True)
        username = Column(String(255))  # TODO: remove
        password = Column(String(255))
        last_login_at = Column(DateTime())
        current_login_at = Column(DateTime())
        last_login_ip = Column(String(100))
        current_login_ip = Column(String(100))
        login_count = Column(Integer)
        active = Column(Boolean())
        confirmed_at = Column(DateTime())
        roles = relationship('Role', secondary='roles_users',
                             backref=backref('users', lazy='dynamic'))

    with email_app.app_context():
        Base.metadata.create_all(bind=engine)

    def tear_down():
        db_session.close()
        os.close(f)
        os.remove(path)
    request.addfinalizer(tear_down)

    return SQLAlchemySessionUserDatastore(db_session, User, Role)


@pytest.fixture()
def sqlalchemy_session_username_datastore(request, username_app, tmpdir):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker, relationship, \
        backref
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Boolean, DateTime, Column, Integer, String, \
        ForeignKey

    f, path = tempfile.mkstemp(
        prefix='flask-security-test-db', suffix='.db', dir=str(tmpdir))

    username_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path

    engine = create_engine(username_app.config['SQLALCHEMY_DATABASE_URI'],
                           convert_unicode=True)
    db_session = scoped_session(sessionmaker(autocommit=False,
                                             autoflush=False,
                                             bind=engine))
    Base = declarative_base()
    Base.query = db_session.query_property()

    class RolesUsers(Base):
        __tablename__ = 'roles_users'
        id = Column(Integer(), primary_key=True)
        user_id = Column('user_id', Integer(), ForeignKey('user.id'))
        role_id = Column('role_id', Integer(), ForeignKey('role.id'))

    class Role(Base, RoleMixin):
        __tablename__ = 'role'
        id = Column(Integer(), primary_key=True)
        name = Column(String(80), unique=True)
        description = Column(String(255))

    class User(Base, UserMixin):
        __tablename__ = 'user'
        id = Column(Integer, primary_key=True)
        username = Column(String(255), unique=True)
        password = Column(String(255))
        last_login_at = Column(DateTime())
        current_login_at = Column(DateTime())
        last_login_ip = Column(String(100))
        current_login_ip = Column(String(100))
        login_count = Column(Integer)
        active = Column(Boolean())
        confirmed_at = Column(DateTime())
        roles = relationship('Role', secondary='roles_users',
                             backref=backref('users', lazy='dynamic'))

    with username_app.app_context():
        Base.metadata.create_all(bind=engine)

    def tear_down():
        db_session.close()
        os.close(f)
        os.remove(path)
    request.addfinalizer(tear_down)

    return SQLAlchemySessionUserDatastore(db_session, User, Role)


@pytest.fixture()
def sqlalchemy_session_datastore(app,
                                 sqlalchemy_session_email_datastore,
                                 sqlalchemy_session_username_datastore):
    if app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] == ["email"]:
        return sqlalchemy_session_email_datastore
    else:
        return sqlalchemy_session_username_datastore


@pytest.fixture()
def peewee_email_datastore(request, email_app, tmpdir):
    from peewee import TextField, DateTimeField, IntegerField, BooleanField, \
        ForeignKeyField
    from flask_peewee.db import Database

    f, path = tempfile.mkstemp(
        prefix='flask-security-test-db', suffix='.db', dir=str(tmpdir))

    email_app.config['DATABASE'] = {
        'name': path,
        'engine': 'peewee.SqliteDatabase'
    }

    db = Database(email_app)

    class Role(db.Model, RoleMixin):
        name = TextField(unique=True)
        description = TextField(null=True)

    class User(db.Model, UserMixin):
        email = TextField()
        username = TextField(null=True)  # TODO: remove
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

    with email_app.app_context():
        for Model in (Role, User, UserRoles):
            Model.create_table()

    def tear_down():
        db.close_db(None)
        os.close(f)
        os.remove(path)

    request.addfinalizer(tear_down)

    return PeeweeUserDatastore(db, User, Role, UserRoles)


@pytest.fixture()
def peewee_username_datastore(request, username_app, tmpdir):
    from peewee import TextField, DateTimeField, IntegerField, BooleanField, \
        ForeignKeyField
    from flask_peewee.db import Database

    f, path = tempfile.mkstemp(
        prefix='flask-security-test-db', suffix='.db', dir=str(tmpdir))

    username_app.config['DATABASE'] = {
        'name': path,
        'engine': 'peewee.SqliteDatabase'
    }

    db = Database(username_app)

    class Role(db.Model, RoleMixin):
        name = TextField(unique=True)
        description = TextField(null=True)

    class User(db.Model, UserMixin):
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

    with username_app.app_context():
        for Model in (Role, User, UserRoles):
            Model.create_table()

    def tear_down():
        db.close_db(None)
        os.close(f)
        os.remove(path)

    request.addfinalizer(tear_down)

    return PeeweeUserDatastore(db, User, Role, UserRoles)


@pytest.fixture()
def peewee_datastore(app,
                     peewee_email_datastore,
                     peewee_username_datastore):
    if app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] == ["email"]:
        return peewee_email_datastore
    else:
        return peewee_username_datastore


@pytest.fixture()
def pony_email_datastore(request, email_app, tmpdir):
    from pony.orm import Database, Optional, Required, Set
    from pony.orm.core import SetInstance

    SetInstance.append = SetInstance.add
    db = Database()

    class Role(db.Entity):
        name = Required(str, unique=True)
        description = Optional(str, nullable=True)
        users = Set(lambda: User)

    class User(db.Entity):
        email = Required(str)
        username = Optional(str)  # TODO: remove
        password = Optional(str, nullable=True)
        last_login_at = Optional(datetime)
        current_login_at = Optional(datetime)
        last_login_ip = Optional(str)
        current_login_ip = Optional(str)
        login_count = Optional(int)
        active = Required(bool, default=True)
        confirmed_at = Optional(datetime)
        roles = Set(lambda: Role)

        def has_role(self, name):
            return name in {r.name for r in self.roles.copy()}

    email_app.config['DATABASE'] = {
        'name': ':memory:',
        'engine': 'pony.SqliteDatabase'
    }

    db.bind('sqlite', ':memory:', create_db=True)
    db.generate_mapping(create_tables=True)

    return PonyUserDatastore(db, User, Role)


@pytest.fixture()
def pony_username_datastore(request, username_app, tmpdir):
    from pony.orm import Database, Optional, Required, Set
    from pony.orm.core import SetInstance

    SetInstance.append = SetInstance.add
    db = Database()

    class Role(db.Entity):
        name = Required(str, unique=True)
        description = Optional(str, nullable=True)
        users = Set(lambda: User)

    class User(db.Entity):
        username = Required(str)
        password = Optional(str, nullable=True)
        last_login_at = Optional(datetime)
        current_login_at = Optional(datetime)
        last_login_ip = Optional(str)
        current_login_ip = Optional(str)
        login_count = Optional(int)
        active = Required(bool, default=True)
        confirmed_at = Optional(datetime)
        roles = Set(lambda: Role)

        def has_role(self, name):
            return name in {r.name for r in self.roles.copy()}

    username_app.config['DATABASE'] = {
        'name': ':memory:',
        'engine': 'pony.SqliteDatabase'
    }

    db.bind('sqlite', ':memory:', create_db=True)
    db.generate_mapping(create_tables=True)

    return PonyUserDatastore(db, User, Role)


@pytest.fixture()
def pony_datastore(app,
                   pony_email_datastore,
                   pony_username_datastore):
    if app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] == ["email"]:
        return pony_email_datastore
    else:
        return pony_username_datastore


@pytest.fixture()
def sqlalchemy_app(app, sqlalchemy_datastore):
    def create():
        app.security = Security(app, datastore=sqlalchemy_datastore)
        return app
    return create


@pytest.fixture()
def sqlalchemy_session_app(app, sqlalchemy_session_datastore):
    def create():
        app.security = Security(app, datastore=sqlalchemy_session_datastore)
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
def pony_app(app, pony_datastore):
    def create():
        app.security = Security(app, datastore=pony_datastore)
        return app
    return create


@pytest.fixture()
def client(request, sqlalchemy_app):
    app = sqlalchemy_app()
    populate_data(app)
    return app.test_client()


@pytest.yield_fixture()
def in_app_context(request, sqlalchemy_app):
    app = sqlalchemy_app()
    with app.app_context():
        yield app


@pytest.fixture()
def get_message(app):
    def fn(key, **kwargs):
        rv = app.config['SECURITY_MSG_' + key][0] % kwargs
        return rv.encode('utf-8')
    return fn


@pytest.fixture(params=['sqlalchemy', 'sqlalchemy-session', 'mongoengine',
                        'peewee', 'pony'])
def email_datastore(
        request,
        sqlalchemy_email_datastore,
        sqlalchemy_session_email_datastore,
        mongoengine_email_datastore,
        peewee_email_datastore,
        pony_email_datastore):
    if request.param == 'sqlalchemy':
        rv = sqlalchemy_email_datastore
    elif request.param == 'sqlalchemy-session':
        rv = sqlalchemy_session_email_datastore
    elif request.param == 'mongoengine':
        rv = mongoengine_email_datastore
    elif request.param == 'peewee':
        rv = peewee_email_datastore
    elif request.param == 'pony':
        rv = pony_email_datastore
    return rv


@pytest.fixture(params=['sqlalchemy', 'sqlalchemy-session', 'mongoengine',
                        'peewee', 'pony'])
def username_datastore(
        request,
        sqlalchemy_username_datastore,
        sqlalchemy_session_username_datastore,
        mongoengine_username_datastore,
        peewee_username_datastore,
        pony_username_datastore):
    if request.param == 'sqlalchemy':
        rv = sqlalchemy_username_datastore
    elif request.param == 'sqlalchemy-session':
        rv = sqlalchemy_session_username_datastore
    elif request.param == 'mongoengine':
        rv = mongoengine_username_datastore
    elif request.param == 'peewee':
        rv = peewee_username_datastore
    elif request.param == 'pony':
        rv = pony_username_datastore
    return rv


@pytest.fixture()
def datastore(app,
              email_datastore,
              username_datastore):
    if app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] == ["email"]:
        return email_datastore
    else:
        return username_datastore


@pytest.fixture()
def email_script_info(email_app, email_datastore):
    try:
        from flask.cli import ScriptInfo
    except ImportError:
        from flask_cli import ScriptInfo

    def create_app(info):
        email_app.security = Security(email_app, datastore=email_datastore)
        return email_app
    return ScriptInfo(create_app=create_app)


@pytest.fixture()
def username_script_info(username_app, username_datastore):
    try:
        from flask.cli import ScriptInfo
    except ImportError:
        from flask_cli import ScriptInfo

    def create_app(info):
        username_app.security = Security(username_app,
                                         datastore=username_datastore)
        return username_app
    return ScriptInfo(create_app=create_app)


@pytest.fixture()
def script_info(app, email_script_info, username_script_info):
    if app.config["SECURITY_USER_IDENTITY_ATTRIBUTES"] == ["email"]:
        return email_script_info
    else:
        return username_script_info
