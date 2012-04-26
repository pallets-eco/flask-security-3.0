.. Flask-Security documentation master file, created by
   sphinx-quickstart on Mon Mar 12 15:35:21 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Flask-Security
==============

.. module:: flask_security

Simple security for Flask applications combining 
`Flask-Login <http://packages.python.org/Flask-Login/>`_, 
`Flask-Principal <http://packages.python.org/Flask-Principal/>`_, 
`Flask-WTF <http://packages.python.org/Flask-WTF/>`_, 
`passlib <http://packages.python.org/passlib/>`_, and your choice of datastore. 
Currently `SQLAlchemy <http://www.sqlalchemy.org>`_ via 
`Flask-SQLAlchemy <http://packages.python.org/Flask-SQLAlchemy/>`_ and 
`MongoEngine <http://www.mongoengine.org/>`_ via 
`Flask-MongoEngine <https://github.com/sbook/flask-mongoengine/>`_ are supported 
out of the box. You will need to install the necessary Flask extensions that 
you'll be using on your own. Additionally, you may need to install an encryption 
library such as `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_ (if 
you plan to use bcrypt) for your desired encryption method.


Contents
=========
* :ref:`overview`
* :ref:`installation`
* :ref:`getting-started`
* :ref:`additional-user-fields`
* :ref:`flask-script-commands`
* :ref:`api`
* :doc:`Changelog </changelog>`


.. _overview:

Overview
========

Flask-Security does a few things that Flask-Login and Flask-Principal don't 
provide out of the box. They are:

1. Setting up login and logout endpoints
2. Authenticating users based on username or email
3. Limiting access based on user 'roles'
4. User and role creation
5. Password encryption

That being said, you can still hook into things such as the Flask-Login and 
Flask-Principal signals if need be.


.. _installation:

Installation
============

First, install Flask-Security::

    $ mkvirtualenv app-name
    $ pip install Flask-Security
    
Then install your datastore requirement. 

**SQLAlchemy**::

    $ pip install Flask-SQLAlchemy
    
**MongoEngine**::

    $ pip install https://github.com/sbook/flask-mongoengine/tarball/master


.. _getting-started:

Getting Started
===============

The following code samples will illustrate how to get started using SQLAlchemy. 
First thing you'll want to do is setup your application and datastore::

    from flask import Flask, render_template
    from flask.ext.sqlalchemy import SQLAlchemy
    from flask.ext.security import (User, Security, LoginForm,  login_required, 
                                    roles_accepted, user_datastore)
    from flask.ext.security.datastore.sqlalchemy import SQLAlchemyUserDataStore
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    db = SQLAlchemy(app)
    Security(app, SQLAlchemyUserDatastore(db))

You'll probably want to at least one user to the database to test this out. 
There are many ways to do this, but this is a quick and dirty way to do it::

    @app.before_first_request
    def before_first_request():
        user_datastore.create_role(name='admin')
        user_datastore.create_user(username='matt', email='matt@something.com',
                                   password='password', roles=['admin'])
        
Next you'll want to setup your login screen. Setup your view::

    @app.route("/login")
    def login():
        return render_template('login.html', form=LoginForm())
    
And corresponding template::

    <form action="{{ url_for('auth.authenticate') }}" method="POST">
      {{ form.hidden_tag() }}
      {{ form.username.label }} {{ form.username }}<br/>
      {{ form.password.label }} {{ form.password }}<br/>
      {{ form.remember.label }} {{ form.remember }}<br/>
      {{ form.submit }}
    </form>
    
By default, Flask-Security will redirect a user to `/profile` after logging in. 
You can set this page up yourself or set the `SECURITY_POST_LOGIN` config 
value to change this behavior. Regardless, setup a protected view as such::

    @app.route('/profile')
    @login_required
    def profile():
        return render_template('profile.html')
         
Now you have an application with basic authentication. If you run the local 
development server you can visit `http://localhost:5000/login <http://localhost:5000/login>`_ 
to login.

The last thing you'll want to do is add a logout link to your templates. This 
can be achieved with::

    <a href="{{ url_for('auth.logout') }}">Logout</a>
    
Now, for instance, say you want to protect an admin area to users that are 
administrators. You can use the `roles_accepted` decorator to prevent access. 
The corresponding view would look like such::

    @app.route('/admin')
    @roles_accepted('admin')
    def admin():
        return render_template('admin/index.html')
        
And lastly, maybe you only want to show something in a template if a user has a 
specific role::

    {% if current_user.has_role('admin') %}
      <a href="{{ url_for('admin.index') }}">Admin Panel</a>
    {$ endif %}


.. _additional-user-fields:

Additional User Fields
----------------------
If you'd like to add additional fields to the user model you can use a mixin
class that specifies your additional fields. The following is an example of
how you might do this::

    db = SQLAlchemy(app)

    class UserAccountMixin():
        first_name = db.Column(db.String(120))
        last_name = db.Column(db.String(120))

    Security(app, SQLAlchemyUserDatastore(db, UserAccountMixin))

.. _flask-script-commands:

Flask-Script Commands
---------------------
Flask-Security comes packed with a few Flask-Script commands. They are:

* :class:`flask.ext.security.script.CreateUserCommand`
* :class:`flask.ext.security.script.CreateRoleCommand`
* :class:`flask.ext.security.script.AddRoleCommand`
* :class:`flask.ext.security.script.RemoveRoleCommand`
* :class:`flask.ext.security.script.DeactivateUserCommand`
* :class:`flask.ext.security.script.ActivateUserCommand`

Register these on your script manager for pure convenience.
        

.. _configuration:

Configuration Values
====================

* :attr:`SECURITY_URL_PREFIX`: Specifies the URL prefix for the Security 
  blueprint
* :attr:`SECURITY_AUTH_PROVIDER`: Specifies the class to use as the 
  authentication provider. Such as `flask.ext.security.AuthenticationProvider`
* :attr:`SECURITY_PASSWORD_HASH`: Specifies the encryption method to use. e.g.: 
  plaintext, bcrypt, etc
* :attr:`SECURITY_USER_DATASTORE`: Specifies the property name to use for the 
  user datastore on the application instance
* :attr:`SECURITY_LOGIN_FORM`: Specifies the form class to use when processing 
  an authentication request
* :attr:`SECURITY_AUTH_URL`: Specifies the URL to to handle authentication 
* :attr:`SECURITY_LOGOUT_URL`: Specifies the URL to process a logout request
* :attr:`SECURITY_LOGIN_VIEW`: Specifies the URL to redirect to when 
  authentication is required
* :attr:`SECURITY_POST_LOGIN`: Specifies the URL to redirect to after a user is 
  authenticated
* :attr:`SECURITY_POST_LOGOUT`: Specifies the URL to redirect to after a user 
  logs out
* :attr:`SECURITY_FLASH_MESSAGES`: Specifies wether or not to flash messages 
  during authentication request


.. _api:

API
===

.. autoclass:: flask_security.Security
    :members:

.. data:: flask_security.current_user

   A proxy for the current user.
   

Protecting Views
----------------
.. autofunction:: flask_security.login_required
    
.. autofunction:: flask_security.roles_required

.. autofunction:: flask_security.roles_accepted


User Object Helpers
-------------------
.. autoclass:: flask_security.UserMixin
   :members:
   
.. autoclass:: flask_security.RoleMixin
   :members:

.. autoclass:: flask_security.AnonymousUser
   :members:


Datastores
----------
.. autoclass:: flask_security.datastore.UserDatastore
    :members:
    
.. autoclass:: flask_security.datastore.sqlalchemy.SQLAlchemyUserDatastore
    :members:
    :inherited-members:
    
.. autoclass:: flask_security.datastore.mongoengine.MongoEngineUserDatastore
    :members:
    :inherited-members:


Models
------
.. autoclass:: flask_security.User
    
    .. attribute:: id
       
       User ID
       
    .. attribute:: username
       
       Username
       
    .. attribute:: email
       
       Email address
       
    .. attribute:: password
    
       Password
       
    .. attribute:: active
    
       Active state
       
    .. attribute:: roles
    
       User roles
       
    .. attribute:: created_at
    
       Created date
       
    .. attribute:: modified_at
    
       Modified date
        
        
.. autoclass:: flask_security.Role

    .. attribute:: id
    
       Role ID
       
    .. attribute:: name
    
       Role name
       
    .. attribute:: description
    
       Role description
       

Exceptions
----------    
.. autoexception:: flask_security.BadCredentialsError

.. autoexception:: flask_security.AuthenticationError

.. autoexception:: flask_security.UserNotFoundError

.. autoexception:: flask_security.RoleNotFoundError

.. autoexception:: flask_security.UserIdNotFoundError

.. autoexception:: flask_security.UserDatastoreError

.. autoexception:: flask_security.UserCreationError

.. autoexception:: flask_security.RoleCreationError


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