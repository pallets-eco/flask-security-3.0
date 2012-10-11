# -*- coding: utf-8 -*-
"""
    flask.ext.security.views
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app, redirect, request, render_template, jsonify, \
     after_this_request, Blueprint
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from .confirmable import send_confirmation_instructions, \
     confirm_user, confirm_email_token_status
from .decorators import login_required, anonymous_user_required
from .forms import LoginForm, ConfirmRegisterForm, RegisterForm, \
     ForgotPasswordForm, ResetPasswordForm, SendConfirmationForm, \
     PasswordlessLoginForm
from .passwordless import send_login_instructions, \
     login_token_status
from .recoverable import reset_password_token_status, \
     send_reset_password_instructions, update_password
from .registerable import register_user
from .utils import get_url, get_post_login_redirect, do_flash, \
     get_message, login_user, logout_user, url_for_security as url_for


# Convenient references
_security = LocalProxy(lambda: current_app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def _render_json(form, include_auth_token=False):
    has_errors = len(form.errors) > 0

    if has_errors:
        code = 400
        response = dict(errors=form.errors)
    else:
        code = 200
        response = dict(user=dict(id=str(form.user.id)))
        if include_auth_token:
            token = form.user.get_auth_token()
            response['user']['authentication_token'] = token

    return jsonify(dict(meta=dict(code=code), response=response))


def _commit(response=None):
    _datastore.commit()
    return response


def _ctx(endpoint):
    return _security._run_ctx_processor(endpoint)


@anonymous_user_required
def login():
    """View function for login view"""

    if request.json:
        form = LoginForm(MultiDict(request.json))
    else:
        form = LoginForm()

    if form.validate_on_submit():
        login_user(form.user, remember=form.remember.data)
        after_this_request(_commit)

        if not request.json:
            return redirect(get_post_login_redirect())

    if request.json:
        return _render_json(form, True)

    return render_template('security/login_user.html',
                           login_user_form=form,
                           **_ctx('login'))


@login_required
def logout():
    """View function which handles a logout request."""

    logout_user()

    return redirect(request.args.get('next', None) or
                    get_url(_security.post_logout_view))


def register():
    """View function which handles a registration request."""

    if _security.confirmable or request.json:
        form_class = ConfirmRegisterForm
    else:
        form_class = RegisterForm

    if request.json:
        form_data = MultiDict(request.json)
    else:
        form_data = request.form

    form = form_class(form_data)

    if form.validate_on_submit():
        user = register_user(**form.to_dict())
        form.user = user

        if not _security.confirmable or _security.login_without_confirmation:
            after_this_request(_commit)
            login_user(user)

        if not request.json:
            post_register_url = get_url(_security.post_register_view)
            post_login_url = get_url(_security.post_login_view)
            return redirect(post_register_url or post_login_url)

    if request.json:
        return _render_json(form)

    return render_template('security/register_user.html',
                           register_user_form=form,
                           **_ctx('register'))


def send_login():
    """View function that sends login instructions for passwordless login"""

    if request.json:
        form = PasswordlessLoginForm(MultiDict(request.json))
    else:
        form = PasswordlessLoginForm()

    if form.validate_on_submit():
        send_login_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('LOGIN_EMAIL_SENT', email=form.user.email))

    if request.json:
        return _render_json(form)

    return render_template('security/send_login.html',
                           send_login_form=form,
                           **_ctx('send_login'))


@anonymous_user_required
def token_login(token):
    """View function that handles passwordless login via a token"""

    expired, invalid, user = login_token_status(token)

    if invalid:
        do_flash(*get_message('INVALID_LOGIN_TOKEN'))
    if expired:
        send_login_instructions(user)
        do_flash(*get_message('LOGIN_EXPIRED', email=user.email,
                              within=_security.login_within))
    if invalid or expired:
        return redirect(url_for('login'))

    login_user(user, True)
    after_this_request(_commit)
    do_flash(*get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'))

    return redirect(get_post_login_redirect())


def send_confirmation():
    """View function which sends confirmation instructions."""

    if request.json:
        form = SendConfirmationForm(MultiDict(request.json))
    else:
        form = SendConfirmationForm()

    if form.validate_on_submit():
        send_confirmation_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('CONFIRMATION_REQUEST', email=form.user.email))

    if request.json:
        return _render_json(form)

    return render_template('security/send_confirmation.html',
                           send_confirmation_form=form,
                           **_ctx('send_confirmation'))


@anonymous_user_required
def confirm_email(token):
    """View function which handles a email confirmation request."""

    expired, invalid, user = confirm_email_token_status(token)

    if invalid:
        do_flash(*get_message('INVALID_CONFIRMATION_TOKEN'))
    if expired:
        send_confirmation_instructions(user)
        do_flash(*get_message('CONFIRMATION_EXPIRED', email=user.email,
                              within=_security.confirm_email_within))
    if invalid or expired:
        return redirect(get_url(_security.confirm_error_view) or
                        url_for('send_confirmation'))

    confirm_user(user)
    login_user(user, True)
    after_this_request(_commit)
    do_flash(*get_message('EMAIL_CONFIRMED'))

    return redirect(get_url(_security.post_confirm_view) or
                    get_url(_security.post_login_view))


def forgot_password():
    """View function that handles a forgotten password request."""

    if request.json:
        form = ForgotPasswordForm(MultiDict(request.json))
    else:
        form = ForgotPasswordForm()

    if form.validate_on_submit():
        send_reset_password_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('PASSWORD_RESET_REQUEST', email=form.user.email))

    if request.json:
        return _render_json(form)

    return render_template('security/forgot_password.html',
                           forgot_password_form=form,
                           **_ctx('forgot_password'))


@anonymous_user_required
def reset_password(token):
    """View function that handles a reset password request."""

    expired, invalid, user = reset_password_token_status(token)

    if invalid:
        do_flash(*get_message('INVALID_RESET_PASSWORD_TOKEN'))
    if expired:
        do_flash(*get_message('PASSWORD_RESET_EXPIRED', email=user.email,
                              within=_security.reset_password_within))
    if invalid or expired:
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        after_this_request(_commit)
        update_password(user, form.password.data)
        do_flash(*get_message('PASSWORD_RESET'))
        login_user(user, True)
        return redirect(get_url(_security.post_reset_view) or
                        get_url(_security.post_login_view))

    return render_template('security/reset_password.html',
                           reset_password_form=form,
                           reset_password_token=token,
                           **_ctx('reset_password'))


def create_blueprint(state, import_name):
    """Creates the security extension blueprint"""

    bp = Blueprint(state.blueprint_name, import_name,
                   url_prefix=state.url_prefix,
                   template_folder='templates')

    bp.route(state.logout_url, endpoint='logout')(logout)

    if state.passwordless:
        bp.route(state.login_url,
                 methods=['GET', 'POST'],
                 endpoint='login')(send_login)
        bp.route(state.login_url + '/<token>',
                 endpoint='token_login')(token_login)
    else:
        bp.route(state.login_url,
                 methods=['GET', 'POST'],
                 endpoint='login')(login)

    if state.registerable:
        bp.route(state.register_url,
                 methods=['GET', 'POST'],
                 endpoint='register')(register)

    if state.recoverable:
        bp.route(state.reset_url,
                 methods=['GET', 'POST'],
                 endpoint='forgot_password')(forgot_password)
        bp.route(state.reset_url + '/<token>',
                 methods=['GET', 'POST'],
                 endpoint='reset_password')(reset_password)

    if state.confirmable:
        bp.route(state.confirm_url,
                 methods=['GET', 'POST'],
                 endpoint='send_confirmation')(send_confirmation)
        bp.route(state.confirm_url + '/<token>',
                 methods=['GET', 'POST'],
                 endpoint='confirm_email')(confirm_email)

    return bp
