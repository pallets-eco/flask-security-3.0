# a little trick so you can run:
# $ python example/app.py 
# from the root of the security project
import sys, os
sys.path.pop(0)
sys.path.insert(0, os.getcwd())

from flask import Flask, render_template

from flask.ext.mongoengine import MongoEngine
from flask.ext.sqlalchemy import SQLAlchemy

from flask.ext.security import (Security, LoginForm, user_datastore, 
                                login_required, roles_required, roles_accepted)

from flask.ext.security.datastore.sqlalchemy import SQLAlchemyUserDatastore
from flask.ext.security.datastore.mongoengine import MongoEngineUserDatastore

def create_roles():
    for role in ('admin', 'editor', 'author'):
        user_datastore.create_role(name=role)
        
def create_users():
    for u in  (('matt','matt@lp.com','password',['admin'],True),
               ('joe','joe@lp.com','password',['editor'],True),
               ('jill','jill@lp.com','password',['author'],True),
               ('tiya','tiya@lp.com','password',[],False)):
        user_datastore.create_user(username=u[0], email=u[1], password=u[2], 
                                   roles=u[3], active=u[4])

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
    
    @app.route('/post_logout')
    def post_logout():
        return render_template('index.html', content='Post Logout')
    
    @app.route('/admin')
    @roles_required('admin')
    def admin():
        return render_template('index.html', content='Admin Page')
    
    @app.route('/admin_or_editor')
    @roles_accepted('admin', 'editor')
    def admin_or_editor():
        return render_template('index.html', content='Admin or Editor Page')
    
    return app

def create_sqlalchemy_app(auth_config=None):
    app = create_app(auth_config)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/flask_security_example.sqlite'
    
    db = SQLAlchemy(app)

    class UserAccountMixin():
        first_name = db.Column(db.String(120))
        last_name = db.Column(db.String(120))

    Security(app, SQLAlchemyUserDatastore(db, UserAccountMixin))
    
    @app.before_first_request
    def before_first_request():
        db.drop_all()
        db.create_all()
        populate_data()
        
    return app

def create_mongoengine_app(auth_config=None):
    app = create_app(auth_config)
    app.config['MONGODB_DB'] = 'flask_security_example'
    app.config['MONGODB_HOST'] = 'localhost'
    app.config['MONGODB_PORT'] = 27017
    
    db = MongoEngine(app)

    class UserAccountMixin():
        first_name = db.StringField(max_length=120)
        last_name = db.StringField(max_length=120)

    Security(app, MongoEngineUserDatastore(db, UserAccountMixin))
    
    @app.before_first_request
    def before_first_request():
        from flask.ext.security import User, Role
        User.drop_collection()
        Role.drop_collection()
        populate_data()
        
    return app

if __name__ == '__main__':
    app = create_sqlalchemy_app()
    #app = create_mongoengine_app()
    app.run()