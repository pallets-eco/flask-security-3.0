Quick Start
===========

-  `Basic SQLAlchemy Application <#basic-sqlalchemy-application>`_
-  `Basic MongoEngine Application <#basic-mongoengine-application>`_
-  `Basic Peewee Application <#basic-peewee-application>`_
-  `Mail Configuration <#mail-configuration>`_

Basic SQLAlchemy Application
=============================

SQLAlchemy Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     $ mkvirtualenv <your-app-name>
     $ pip install flask-security sqlalchemy


SQLAlchemy Application
~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using SQLAlchemy:

::

    from flask import Flask, render_template
    from flask.ext.sqlalchemy import SQLAlchemy
    from flask.ext.security import Security, SQLAlchemyUserDatastore, \
        UserMixin, RoleMixin, login_required

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    # Create database connection object
    db = SQLAlchemy(app)

    # Define models
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
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship('Role', secondary=roles_users,
                                backref=db.backref('users', lazy='dynamic'))

    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db.session, User, Role)
    security = Security(app, user_datastore)

    # Create a user to test with
    @app.before_first_request
    def create_user():
        db.create_all()
        user_datastore.create_user(email='matt@nobien.net', password='password')
        db.session.commit()

    # Views
    @app.route('/')
    @login_required
    def home():
        return render_template('index.html')

    if __name__ == '__main__':
        app.run()


Basic MongoEngine Application
==============================

MongoEngine Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ mkvirtualenv <your-app-name>
    $ pip install flask-security flask-mongoengine

MongoEngine Application
~~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using MongoEngine:

::

    from flask import Flask, render_template
    from flask.ext.mongoengine import MongoEngine
    from flask.ext.security import Security, MongoEngineUserDatastore, \
        UserMixin, RoleMixin, login_required

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'super-secret'

    # MongoDB Config
    app.config['MONGODB_DB'] = 'mydatabase'
    app.config['MONGODB_HOST'] = 'localhost'
    app.config['MONGODB_PORT'] = 27017

    # Create database connection object
    db = MongoEngine(app)

    class Role(db.Document, RoleMixin):
        name = db.StringField(max_length=80, unique=True)
        description = db.StringField(max_length=255)

    class User(db.Document, UserMixin):
        email = db.StringField(max_length=255)
        password = db.StringField(max_length=255)
        active = db.BooleanField(default=True)
        confirmed_at = db.DateTimeField()
        roles = db.ListField(db.ReferenceField(Role), default=[])

    # Setup Flask-Security
    user_datastore = MongoEngineUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    # Create a user to test with
    @app.before_first_request
    def create_user():
        user_datastore.create_user(email='matt@nobien.net', password='password')

    # Views
    @app.route('/')
    @login_required
    def home():
        return render_template('index.html')

    if __name__ == '__main__':
        app.run()


Basic Peewee Application
========================

Peewee Install requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ mkvirtualenv <your-app-name>
    $ pip install flask-security flask-peewee

Peewee Application
~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using Peewee:

::

    from flask import Flask, render_template
    from flask_peewee.db import Database
    from peewee import *
    from flask.ext.security import Security, PeeweeUserDatastore, \
        UserMixin, RoleMixin, login_required

    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['DATABASE'] = {
        'name': 'example.db',
        'engine': 'peewee.SqliteDatabase',
    }

    # Create database connection object
    db = Database(app)

    class Role(db.Model, RoleMixin):
        name = CharField(unique=True)
        description = TextField(null=True)

    class User(db.Model, UserMixin):
        email = TextField()
        password = TextField()
        active = BooleanField(default=True)
        confirmed_at = DateTimeField(null=True)

    class UserRoles(db.Model):
        # Because peewee does not come with built-in many-to-many
        # relationships, we need this intermediary class to link
        # user to roles.
        user = ForeignKeyField(User, related_name='roles')
        role = ForeignKeyField(Role, related_name='users')
        name = property(lambda self: self.role.name)
        description = property(lambda self: self.role.description)

    # Setup Flask-Security
    user_datastore = PeeweeUserDatastore(db, User, Role, UserRoles)
    security = Security(app, user_datastore)

    # Create a user to test with
    @app.before_first_request
    def create_user():
        for Model in (Role, User, UserRoles):
            Model.drop_table(fail_silently=True)
            Model.create_table(fail_silently=True)
        user_datastore.create_user(email='matt@nobien.net', password='password')

    # Views
    @app.route('/')
    @login_required
    def home():
        return render_template('index.html')

    if __name__ == '__main__':
        app.run()


Mail Configuration
===================

Flask-Security integrates with Flask-Mail to handle all email
communications between user and site, so it's important to configure
Flask-Mail with your email server details so Flask-Security can talk
with Flask-Mail correctly.

The following code illustrates a basic setup, which could be added to
the basic application code in the previous section::

    # At top of file
    from flask_mail import Mail

    # After 'Create app'
    app.config['MAIL_SERVER'] = 'smtp.example.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USE_SSL'] = True
    app.config['MAIL_USERNAME'] = 'username'
    app.config['MAIL_PASSWORD'] = 'password'
    mail = Mail(app)

To learn more about the various Flask-Mail settings to configure it to
work with your particular email server configuration, please see the
`Flask-Mail documentation <http://packages.python.org/Flask-Mail/>`_.
