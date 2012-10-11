Quick Start
===========


Installation
------------

Install requirements:

    $ mkvirtualenv <your-app-name>
    $ pip install flask-security, flask-sqlalchemy


Basic Application
-----------------

The following code sample illustrates how to get started as quickly as possible
using SQLAlchemy.::

    from flask import Flask, render_template
    from flask.ext.sqlalchemy import SQLAlchemy
    from flask.ext.security import Security, SQLAlchemyUserDatastore, \
         UserMixin, RoleMixin

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
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    # Create a user to test with
    @app.before_first_request
    def create_user():
        db.create_all()
        user_datastore.create_user(email='matt@nobien.net', password='password')
        db.session.commit()

    # Views
    @app.route('/')
    def home():
        return render_template('index.html')

    if __name__ == '__main__':
        app.run()
