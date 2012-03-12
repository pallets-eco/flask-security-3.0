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

Overview
--------

Flask-Security does a few things that Flask-Login and Flask-Principal don't 
provide out of the box. They are:

1. Setting up login and logout endpoints
2. Authenticating users based on username or email
3. Limiting access based on user 'roles'
4. User and role creation
5. Password encryption

That being said, you can still hook into things such as the Flask-Login and 
Flask-Principal signals if need be.

Installation
------------

First, install Flask-Security::

    $ mkvirtualenv app-name
    $ pip install https://github.com/mattupstate/flask-security/tarball/master
    
Then install your datastore requirement. 

**SQLAlchemy**::

    $ pip install Flask-SQLAlchemy
    
**MongoEngine**::

    $ pip install https://github.com/sbook/flask-mongoengine/tarball/master

Getting Started
---------------

The following code samples will illustrate how to get started using SQLAlchemy. 
First thing you'll want to do is setup your application and datastore::

    from flask import Flask, render_template
    from flask.ext.sqlalchemy import SQLAlchemy
    from flask.ext.security import User, Security, LoginForm, 
                                   login_required, roles_accepted, user_datastore
    from flask.ext.security.datastore.sqlalchemy import SQLAlchemyUserDataStore
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    db = SQLAlchemy(app)
    Security(app, SQLAlchemyUserDatastore(db))

You'll probably want to at least one user to the database to test this out, so 
you can add something such as the following to quickly add an initial user::

    @app.before_first_request
    def before_first_request():
        user_datastore.create_role(name='admin')
        user_datastore.create_user(username='matt', email='matt@something.com',
                                   password='password', roles['admin'])
        
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
        

API
___
.. autoclass:: flask_security.Security
    :members:
    
.. autofunction:: flask_security.roles_required

.. autofunction:: flask_security.roles_accepted

.. autoclass:: flask_security.datastore.UserDatastore
    :members:
    
.. autoclass:: flask_security.datastore.sqlalchemy.SQLAlchemyUserDatastore
    :members:
    
.. autoclass:: flask_security.datastore.mongoengine.MongoEngineUserDatastore
    :members: