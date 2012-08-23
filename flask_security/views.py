# -*- coding: utf-8 -*-
"""
    flask.ext.security.views
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app, redirect, request, \
     render_template, jsonify, after_this_request, Blueprint
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from flask_security.confirmable import send_confirmation_instructions, \
     confirm_by_token
from flask_security.decorators import login_required
from flask_security.exceptions import ConfirmationError, ResetPasswordError, \
     PasswordlessLoginError
from flask_security.forms import LoginForm, ConfirmRegisterForm, RegisterForm, \
     ForgotPasswordForm, ResetPasswordForm, SendConfirmationForm, \
     PasswordlessLoginForm
from flask_security.passwordless import send_login_instructions, login_by_token
from flask_security.recoverable import reset_by_token, \
     send_reset_password_instructions
from flask_security.registerable import register_user
from flask_security.utils import get_url, get_post_login_redirect, do_flash, \
     get_message, config_value, login_user, logout_user, \
     anonymous_user_required, url_for_security as url_for


# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def _render_json(form):
    has_errors = len(form.errors) > 0

    if has_errors:
        code = 400
        response = dict(errors=form.errors)
    else:
        code = 200
        response = dict(user=dict(id=str(form.user.id),
                        authentication_token=form.user.get_auth_token()))

    return jsonify(dict(meta=dict(code=code), response=response))


def _commit(response=None):
    _datastore._commit()
    return response


def _ctx(endpoint):
    return _security._run_ctx_processor(endpoint)


@anonymous_user_required
def login():
    """View function for login view"""

    form_data = request.form

    if request.json:
        form_data = MultiDict(request.json)

    form = LoginForm(form_data, csrf_enabled=not app.testing)

    if form.validate_on_submit():
        login_user(form.user, remember=form.remember.data)
        after_this_request(_commit)

        if not request.json:
            return redirect(get_post_login_redirect())

    if request.json:
        return _render_json(form)

    return render_template('security/login_user.html',
                           login_user_form=form,
                           **_ctx('login'))


@login_required
def logout():
    """View function which handles a logout request."""

    logout_user()

    return redirect(request.args.get('next', None) or
                    get_url(_security.post_logout_view))


@anonymous_user_required
def register():
    """View function which handles a registration request."""

    if _security.confirmable:
        form = ConfirmRegisterForm
    else:
        form = RegisterForm

    form = form(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        user = register_user(**form.to_dict())

        if not _security.confirmable or _security.login_without_confirmation:
            after_this_request(_commit)
            login_user(user)

        post_register_url = get_url(_security.post_register_view)
        post_login_url = get_url(_security.post_login_view)

        return redirect(post_register_url or post_login_url)

    return render_template('security/register_user.html',
                           register_user_form=form,
                           **_ctx('register'))


@anonymous_user_required
def send_login():
    """View function that sends login instructions for passwordless login"""

    form = PasswordlessLoginForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        send_login_instructions(**form.to_dict())
        do_flash(*get_message('LOGIN_EMAIL_SENT', email=form.user.email))

    return render_template('security/send_login.html',
                           send_login_form=form,
                           **_ctx('send_login'))


@anonymous_user_required
def token_login(token):
    """View function that handles passwordless login via a token"""

    try:
        user, next = login_by_token(token)
    except PasswordlessLoginError, e:
        if e.user:
            send_login_instructions(e.user, e.next)
        do_flash(str(e), 'error')
        return redirect(request.referrer or url_for('login'))

    do_flash(*get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'))
    return redirect(next)


@anonymous_user_required
def send_confirmation():
    """View function which sends confirmation instructions."""

    form = SendConfirmationForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        send_confirmation_instructions(form.user)
        do_flash(*get_message('CONFIRMATION_REQUEST', email=form.user.email))

    return render_template('security/send_confirmation.html',
                           send_confirmation_form=form,
                           **_ctx('send_confirmation'))


def confirm_email(token):
    """View function which handles a email confirmation request."""
    after_this_request(_commit)

    try:
        user = confirm_by_token(token)
    except ConfirmationError, e:
        if e.user:
            send_confirmation_instructions(e.user)
        do_flash(str(e), 'error')
        confirm_error_url = get_url(_security.confirm_error_view)
        return redirect(confirm_error_url or url_for('send_confirmation'))

    do_flash(*get_message('EMAIL_CONFIRMED'))
    login_user(user, True)
    post_confirm_url = get_url(_security.post_confirm_view)
    post_login_url = get_url(_security.post_login_view)
    return redirect(post_confirm_url or post_login_url)


@anonymous_user_required
def forgot_password():
    """View function that handles a forgotten password request."""

    form = ForgotPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        send_reset_password_instructions(form.user)
        do_flash(*get_message('PASSWORD_RESET_REQUEST', email=form.user.email))

    return render_template('security/forgot_password.html',
                           forgot_password_form=form,
                           **_ctx('forgot_password'))


@anonymous_user_required
def reset_password(token):
    """View function that handles a reset password request."""

    next = None
    form = ResetPasswordForm(reset_token=token, csrf_enabled=not app.testing)

    if form.validate_on_submit():
        try:
            user = reset_by_token(token=token, **form.to_dict())
            msg = get_message('PASSWORD_RESET')
            next = (get_url(_security.post_reset_view) or
                    get_url(_security.post_login_view))
        except ResetPasswordError, e:
            msg = (str(e), 'error')
            if e.user:
                send_reset_password_instructions(e.user)

        do_flash(*msg)

    if next:
        login_user(user)
        return redirect(next)

    return render_template('security/reset_password.html',
                           reset_password_form=form,
                           reset_password_token=token,
                           **_ctx('reset_password'))


def create_blueprint(app, name, import_name, **kwargs):
    """Creates the security extension blueprint"""

    bp = Blueprint(name, import_name, **kwargs)

    if config_value('PASSWORDLESS', app=app):
        bp.route(config_value('LOGIN_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='login')(send_login)

        bp.route(config_value('LOGIN_URL', app=app) + '/<token>',
                 methods=['GET'],
                 endpoint='token_login')(token_login)
    else:
        bp.route(config_value('LOGIN_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='login')(login)

    bp.route(config_value('LOGOUT_URL', app=app),
             endpoint='logout')(logout)

    if config_value('REGISTERABLE', app=app):
        bp.route(config_value('REGISTER_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='register')(register)

    if config_value('RECOVERABLE', app=app):
        bp.route(config_value('RESET_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='forgot_password')(forgot_password)
        bp.route(config_value('RESET_URL', app=app) + '/<token>',
                 methods=['GET', 'POST'],
                 endpoint='reset_password')(reset_password)

    if config_value('CONFIRMABLE', app=app):
        bp.route(config_value('CONFIRM_URL', app=app),
                 methods=['GET', 'POST'],
                 endpoint='send_confirmation')(send_confirmation)
        bp.route(config_value('CONFIRM_URL', app=app) + '/<token>',
                 methods=['GET', 'POST'],
                 endpoint='confirm_email')(confirm_email)

    return bp
