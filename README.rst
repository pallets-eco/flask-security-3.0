Flask-Security
===========

|build status|_

.. |build status| image:: https://secure.travis-ci.org/mattupstate/flask-security.png?branch=develop
   :alt: Build Status
.. _build status: http://travis-ci.org/mattupstate/flask-security

Simple security for Flask applications combining Flask-Login, Flask-Principal, 
Flask-WTF, passlib, and your choice of datastore. Currently SQLAlchemy via 
Flask-SQLAlchemy and MongoEngine via Flask-MongoEngine are supported out of the 
box. You will need to install the necessary Flask extensions that you'll be 
using. Additionally, you may need to install an encryption library such as 
py-bcrypt to support bcrypt passwords.

Resources
---------

- `Documentation` <http://packages.python.org/Flask-Security/>`_
- `Issue Tracker <http://github.com/mattupstate/flask-security/issues>`_
- `Code <http://github.com/mattupstate/flask-security/>`_
- `Development Version
  <http://github.com/mattupstate/flask-security/zipball/develop#egg=Flask-Security-dev>`_