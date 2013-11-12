from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import Security, UserMixin, RoleMixin, \
     SQLAlchemyUserDatastore

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

db = SQLAlchemy(app)
db.drop_all()

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
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
    current_login_ip = db.Column(db.String(100))
    login_count = db.Column(db.Integer)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))


db.create_all()
app.security = Security(app, datastore=SQLAlchemyUserDatastore(db, User, Role))
ds = app.extensions['security'].datastore

def create_roles():
    for role in ('admin', 'editor', 'author'):
        ds.create_role(name=role)
    ds.commit()

create_roles()

def create_users(count=None):
    users = [('matt@lp.com', 'password', ['admin'], True),
             ('joe@lp.com', 'password', ['editor'], True),
             ('dave@lp.com', 'password', ['admin', 'editor'], True),
             ('jill@lp.com', 'password', ['author'], True),
             ('tiya@lp.com', 'password', [], False)]
    count = count or len(users)

    for u in users[:count]:
        pw = u[1]#encrypt_password(u[1])
        ds.create_user(email=u[0], password=pw,
                       roles=u[2], active=u[3])
    ds.commit()

create_users(1)
