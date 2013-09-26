# -*- coding: utf-8 -*-

from flask import Flask, render_template, current_app
from flask.ext.mail import Mail
from flask.ext.security import login_required, roles_required, roles_accepted
from flask.ext.security.decorators import http_auth_required, \
     auth_token_required, auth_required
from flask.ext.security.utils import encrypt_password
from werkzeug.local import LocalProxy


ds = LocalProxy(lambda: current_app.extensions['security'].datastore)


def create_app(config):
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = 'secret'
    app.config['TESTING'] = True
    app.config['LOGIN_DISABLED'] = False

    for key, value in config.items():
        app.config[key] = value

    mail = Mail(app)
    app.extensions['mail'] = mail

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

    @app.route('/token')
    @auth_token_required
    def token():
        return render_template('index.html', content='Token Authentication')

    @app.route('/multi_auth')
    @auth_required('session', 'token', 'basic')
    def multi_auth():
        return render_template('index.html', content='Session, Token, Basic auth')

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

    @app.route('/coverage/add_role_to_user')
    def add_role_to_user():
        u = ds.find_user(email='joe@lp.com')
        r = ds.find_role('admin')
        ds.add_role_to_user(u, r)
        return 'success'

    @app.route('/coverage/remove_role_from_user')
    def remove_role_from_user():
        u = ds.find_user(email='matt@lp.com')
        ds.remove_role_from_user(u, 'admin')
        return 'success'

    @app.route('/coverage/deactivate_user')
    def deactivate_user():
        u = ds.find_user(email='matt@lp.com')
        ds.deactivate_user(u)
        return 'success'

    @app.route('/coverage/activate_user')
    def activate_user():
        u = ds.find_user(email='tiya@lp.com')
        ds.activate_user(u)
        return 'success'

    @app.route('/coverage/invalid_role')
    def invalid_role():
        return 'success' if ds.find_role('bogus') is None else 'failure'

    @app.route('/page1')
    def page_1():
        return 'Page 1'

    return app


def create_roles():
    for role in ('admin', 'editor', 'author'):
        ds.create_role(name=role)
    ds.commit()


def create_users(count=None):
    users = [('matt@lp.com', 'password', ['admin'], True),
             ('joe@lp.com', 'password', ['editor'], True),
             ('dave@lp.com', 'password', ['admin', 'editor'], True),
             ('jill@lp.com', 'password', ['author'], True),
             ('tiya@lp.com', 'password', [], False)]
    count = count or len(users)

    for u in users[:count]:
        pw = encrypt_password(u[1])
        ds.create_user(email=u[0], password=pw,
                       roles=u[2], active=u[3])
    ds.commit()


def populate_data(user_count=None):
    create_roles()
    create_users(user_count)


def add_context_processors(saf):
    @saf.form_ctx
    def anyform_for_all():
        return dict()

    @saf.form_ctx
    def forgot_password_ctx():
        return dict()

    @saf.form_ctx
    def login_ctx():
        return dict()

    @saf.form_ctx
    def register_ctx():
        return dict()

    @saf.form_ctx
    def reset_password_ctx():
        return dict()

    @saf.form_ctx
    def send_confirmation_ctx():
        return dict()

    @saf.form_ctx
    def send_login_ctx():
        return dict()

    @saf.form_ctx
    def mail_ctx():
        return dict()
