Overview
========

Flask-Security allows you to quickly add common security mechanisms to your
Flask application. They include:

1. Session based authentication
2. Role management
3. Password encryption
4. Basic HTTP authentication
5. Token based authentication
6. Token based account activation (optional)
7. Token based password recovery/resetting (optional)
8. User registration (optional)
9. Login tracking (optional)

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
connections and model definitions. Flask-Security supports the following Flask
extensions out of the box for data persistance:

1. `Flask-SQLAlchemy <http://packages.python.org/Flask-SQLAlchemy/>`_
2. `Flask-MongoEngine <http://packages.python.org/Flask-MongoEngine/>`_