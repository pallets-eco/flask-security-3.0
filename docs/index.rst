.. include:: ../README.rst


Contents
=========
* :ref:`overview`
* :ref:`installation`
* :ref:`quick-start`
* :ref:`models`
* :ref:`flask-script-commands`
* :ref:`api`
* :doc:`Changelog </changelog>`


.. _overview:

Overview
========

Flask-Security allows you to quickly add common user and security mechanisms to 
your Flask application. They include:

1. Session based authentication
2. Role management
3. Password encryption
4. Basic HTTP authentication
5. Token based authentication
6. Token based account activation (optional)
7. Token based password recovery/resetting (optional)
8. User registration (optional)
9. Login tracking (optional)
10. Basic user management commands

Many of these features are made possible by integrating various Flask extensions
and libraries. They include:

1. `Flask-Login <http://packages.python.org/Flask-Login/>`_
2. `Flask-Mail <http://packages.python.org/Flask-Mail/>`_
3. `Flask-Principal <http://packages.python.org/Flask-Principal/>`_
4. `Flask-Script <http://packages.python.org/Flask-Script/>`_
5. `Flask-WTF <http://packages.python.org/Flask-Mail/>`_
6. `itsdangerous <http://packages.python.org/itsdangerous/>`_
7. `passlib <http://packages.python.org/passlib/>`_

Additionally, it assumes you'll be using a common library for your database 
connections and model definitions. Flask-Security thus supports SQLAlchemy and 
MongoEngine out of the box and additional libraries can easily be supported.


.. _installation:

Installation
============

First, install Flask-Security::

    $ mkvirtualenv app-name
    $ pip install Flask-Security
    
Then install your datastore requirement. 

**SQLAlchemy**::

    $ pip install flask-sqlalchemy
    
**MongoEngine**::

    $ pip install flask-mongoengine

And lastly install any password encryption library that you may need. For 
example::

    $ pip install py-bcrypt


.. _quick-start:

Quick Start Example
===================

The following code sample illustrates how to get started as quickly as possible 
using SQLAlchemy.::

    from flask import Flask, render_template, url_for
    from flask.ext.sqlalchemy import SQLAlchemy
    from flask.ext.security import Security, UserMixin, RoleMixin, \
         login_required
    from flask.ext.security.datastore import SQLAlchemyUserDatastore
    from flask.ext.security.forms import LoginForm

    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SECURITY_POST_LOGIN_VIEW'] = '/protected'

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
        password = db.Column(db.String(255))
        active = db.Column(db.Boolean())
        roles = db.relationship('Role', secondary=roles_users,
                    backref=db.backref('users', lazy='dynamic'))

    datastore = SQLAlchemyUserDatastore(db, User, Role)

    Security(app, datastore)

    @app.before_first_request
    def add_user():
        db.create_all()
        datastore.create_user(email='matt@matt.com',
                              password='password')

    @app.route('/')
    @app.route('/login')
    def login():
        return render_template('security/logins/new.html',
                               login_form=LoginForm())

    @app.route('/protected')
    @login_required
    def protected():
        return """<h1>You are logged in</h1>
                  <p><a href="%s">Log out</a>""" % (
                  url_for('flask_security.logout'))

    if __name__ == '__main__':
        app.run()


.. _models:

Models
======

Flask-Security assumes you'll be using libraries such as SQLAlchemy or 
MongoEngine to define a data model that includes a `User` and `Role` model. The 
fields on your models must follow a particular convention depending on the 
functionality your app requires. Aside from this, you're free to add any 
additional fields to your model(s) if you want. At the bear minimum your `User`
and `Role` model should include the following fields:

**User**

* id
* email
* password
* active

**Role**

* id
* name
* description


Additional Functionality
------------------------

Depending on the application's configuration, additional fields may need to be
added to your `User` model.

Confirmable
^^^^^^^^^^^

If you enable account confirmation by setting your application's 
`SECURITY_CONFIRMABLE` configuration value to `True` your `User` model will 
require the following additional field:

* confirmed_at

Trackable
^^^^^^^^^

If you enable user tracking by setting your application's `SECURITY_TRACKABLE` 
configuration value to `True` your `User` model will require the following 
additional fields:

* last_login_at
* current_login_at
* last_login_ip
* current_login_ip
* login_count


.. _flask-script-commands:

Flask-Script Commands
---------------------
Flask-Security comes packed with a few Flask-Script commands. They are:

* :class:`flask_security.script.CreateUserCommand`
* :class:`flask_security.script.CreateRoleCommand`
* :class:`flask_security.script.AddRoleCommand`
* :class:`flask_security.script.RemoveRoleCommand`
* :class:`flask_security.script.DeactivateUserCommand`
* :class:`flask_security.script.ActivateUserCommand`
* :class:`flask_security.script.ActivateUserCommand`
* :class:`flask_security.script.GenerateBlueprintCommand`

Register these on your script manager for pure convenience.
        

.. _configuration:

Configuration Values
====================

* :attr:`SECURITY_URL_PREFIX`: Specifies the URL prefix for the Security 
  blueprint.
* :attr:`SECURITY_FLASH_MESSAGES`: Specifies wether or not to flash messages 
  during security mechanisms.
* :attr:`SECURITY_PASSWORD_HASH`: Specifies the encryption method to use. e.g.: 
  plaintext, bcrypt, etc.
* :attr:`SECURITY_AUTH_URL`: Specifies the URL to to handle authentication.
* :attr:`SECURITY_LOGOUT_URL`: Specifies the URL to process a logout request.
* :attr:`SECURITY_REGISTER_URL`: Specifies the URL for user registrations.
* :attr:`SECURITY_RESET_URL`: Specifies the URL for password resets.
* :attr:`SECURITY_CONFIRM_URL`: Specifies the URL for account confirmations.
* :attr:`SECURITY_LOGIN_VIEW`: Specifies the URL to redirect to when 
  authentication is required.
* :attr:`SECURITY_CONFIRM_ERROR_VIEW`: Specifies the URL to redirect to when 
  an confirmation error occurs.
* :attr:`SECURITY_POST_LOGIN_VIEW`: Specifies the URL to redirect to after a 
  user logins in.
* :attr:`SECURITY_POST_LOGOUT_VIEW`: Specifies the URL to redirect to after a 
  user logs out.
* :attr:`SECURITY_POST_FORGOT_VIEW`: Specifies the URL to redirect to after a 
  user requests password reset instructions.
* :attr:`SECURITY_RESET_PASSWORD_ERROR_VIEW`: Specifies the URL to redirect to 
  after an error occurs during the password reset process.
* :attr:`SECURITY_POST_REGISTER_VIEW`: Specifies the URL to redirect to after a 
  user successfully registers.
* :attr:`SECURITY_POST_CONFIRM_VIEW`: Specifies the URL to redirect to after a 
  user successfully confirms their account.
* :attr:`SECURITY_UNAUTHORIZED_VIEW`: Specifies the URL to redirect to when a 
  user attempts to access a view they don't have permission to view.
* :attr:`SECURITY_DEFAULT_ROLES`: The default roles any new users should have.
* :attr:`SECURITY_CONFIRMABLE`: Enables confirmation features. Defaults to 
  `False`.
* :attr:`SECURITY_REGISTERABLE`: Enables user registration features. Defaults to 
  `False`.
* :attr:`SECURITY_RECOVERABLE`: Enables password reset/recovery features. 
  Defaults to `False`.
* :attr:`SECURITY_TRACKABLE`: Enables login tracking features. Defaults to 
  `False`.
* :attr:`SECURITY_CONFIRM_EMAIL_WITHIN`: Specifies the amount of time a user
  has to confirm their account/email. Default is `5 days`.
* :attr:`SECURITY_RESET_PASSWORD_WITHIN`: Specifies the amount of time a user
  has to reset their password. Default is `5 days`.
* :attr:`SECURITY_LOGIN_WITHOUT_CONFIRMATION`: Specifies if users can login
  without first confirming their accounts. Defaults to `False`
* :attr:`SECURITY_EMAIL_SENDER`: Specifies the email address to send emails on
  behalf of. Defaults to `no-reply@localhost`.
* :attr:`SECURITY_TOKEN_AUTHENTICATION_KEY`: Specifies the query string argument
  to use during token authentication. Defaults to `auth_token`.
* :attr:`SECURITY_TOKEN_AUTHENTICATION_HEADER`: Specifies the header name to use
  during token authentication. Defaults to `X-Auth-Token`.
* :attr:`SECURITY_CONFIRM_SALT`: Specifies the salt value to use for account 
  confirmation tokens. Defaults to `confirm-salt`.
* :attr:`SECURITY_RESET_SALT`: Specifies the salt value to use for password 
  reset tokens. Defaults to `reset-salt`.
* :attr:`SECURITY_AUTH_SALT`: Specifies the salt value to use for token based
  authentication tokens. Defaults to `auth-salt`.
* :attr:`SECURITY_DEFAULT_HTTP_AUTH_REALM`: Specifies the default basic HTTP
  authentication realm. Defaults to `Login Required`.


.. _api:

API
===

.. autoclass:: flask_security.core.Security
    :members:

.. data:: flask_security.core.current_user

   A proxy for the current user.
   

Protecting Views
----------------
.. autofunction:: flask_security.decorators.login_required
    
.. autofunction:: flask_security.decorators.roles_required

.. autofunction:: flask_security.decorators.roles_accepted

.. autofunction:: flask_security.decorators.http_auth_required

.. autofunction:: flask_security.decorators.auth_token_required


User Object Helpers
-------------------
.. autoclass:: flask_security.core.UserMixin
   :members:
   
.. autoclass:: flask_security.core.RoleMixin
   :members:

.. autoclass:: flask_security.core.AnonymousUser
   :members:


Datastores
----------
.. autoclass:: flask_security.datastore.UserDatastore
    :members:
    
.. autoclass:: flask_security.datastore.SQLAlchemyUserDatastore
    :members:
    :inherited-members:
    
.. autoclass:: flask_security.datastore.MongoEngineUserDatastore
    :members:
    :inherited-members:
       

Exceptions
----------    
.. autoexception:: flask_security.exceptions.BadCredentialsError

.. autoexception:: flask_security.exceptions.AuthenticationError

.. autoexception:: flask_security.exceptions.UserNotFoundError

.. autoexception:: flask_security.exceptions.RoleNotFoundError

.. autoexception:: flask_security.exceptions.UserIdNotFoundError

.. autoexception:: flask_security.exceptions.UserDatastoreError

.. autoexception:: flask_security.exceptions.UserCreationError

.. autoexception:: flask_security.exceptions.RoleCreationError

.. autoexception:: flask_security.exceptions.ConfirmationError

.. autoexception:: flask_security.exceptions.ResetPasswordError


Signals
-------
See the documentation for the signals provided by the Flask-Login and 
Flask-Principal extensions. Flask-Security does not provide any additional 
signals. 


Changelog
=========

.. toctree::
   :maxdepth: 2

   changelog