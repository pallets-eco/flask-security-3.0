# -*- coding: utf-8 -*-
"""
    flask.ext.security.views
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from datetime import datetime

from flask import current_app as app, redirect, request, session, \
     render_template, jsonify
from flask.ext.login import login_user, logout_user
from flask.ext.principal import Identity, AnonymousIdentity, identity_changed
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from .confirmable import confirm_by_token, reset_confirmation_token
from .exceptions import TokenExpiredError, ConfirmationError, \
     BadCredentialsError, ResetPasswordError
from .forms import LoginForm, RegisterForm, ForgotPasswordForm, \
     ResetPasswordForm, ResendConfirmationForm
from .recoverable import reset_by_token, \
     reset_password_reset_token
from .signals import user_registered
from .tokens import generate_authentication_token
from .utils import get_url, get_post_login_redirect, do_flash, \
     get_remember_token


# Convenient references
_security = LocalProxy(lambda: app.security)

_datastore = LocalProxy(lambda: app.security.datastore)

_logger = LocalProxy(lambda: app.logger)


def _do_login(user, remember=True):
    """Performs the login and sends the appropriate signal."""

    if not login_user(user, remember):
        return False

    if user.authentication_token is None:
        user.authentication_token = generate_authentication_token(user)

    if remember:
        user.remember_token = get_remember_token(user.email, user.password)

    if _security.trackable:
        old_current, new_current = user.current_login_at, datetime.utcnow()
        user.last_login_at = old_current or new_current
        user.current_login_at = new_current

        old_current, new_current = user.current_login_ip, request.remote_addr
        user.last_login_ip = old_current or new_current
        user.current_login_ip = new_current

        user.login_count = user.login_count + 1 if user.login_count else 0

    _datastore._save_model(user)

    identity_changed.send(app._get_current_object(),
                          identity=Identity(user.id))

    _logger.debug('User %s logged in' % user)
    return True


def _json_auth_ok(user):
    return jsonify({
        "meta": {
            "code": 200
        },
        "response": {
            "user": {
                "id": str(user.id),
                "authentication_token": user.authentication_token
            }
        }
    })


def _json_auth_error(msg):
    resp = jsonify({
        "meta": {
            "code": 400
        },
        "response": {
            "error": msg
        }
    })
    resp.status_code = 400
    return resp


def authenticate():
    """View function which handles an authentication request."""

    form = LoginForm(MultiDict(request.json) if request.json else request.form)

    try:
        user = _security.auth_provider.authenticate(form)

        if _do_login(user, remember=form.remember.data):
            if request.json:
                return _json_auth_ok(user)

            return redirect(get_post_login_redirect())

        raise BadCredentialsError('Inactive user')

    except BadCredentialsError, e:
        msg = str(e)

    _logger.debug('Unsuccessful authentication attempt: %s' % msg)

    if request.json:
        return _json_auth_error(msg)

    do_flash(msg, 'error')

    return redirect(request.referrer or _security.login_manager.login_view)


def logout():
    """View function which handles a logout request."""

    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    identity_changed.send(app._get_current_object(),
                          identity=AnonymousIdentity())

    logout_user()
    _logger.debug('User logged out')

    return redirect(request.args.get('next', None) or
                    _security.post_logout_view)


def register_user():
    """View function which handles a registration request."""

    form = RegisterForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        # Create user
        u = _datastore.create_user(**form.to_dict())

        # Send confirmation instructions if necessary
        t = reset_confirmation_token(u) if _security.confirmable else None

        data = dict(user=u, confirm_token=t)
        user_registered.send(data, app=app._get_current_object())

        _logger.debug('User %s registered' % u)

        # Login the user if allowed
        if not _security.confirmable or _security.login_without_confirmation:
            _do_login(u)

        return redirect(_security.post_register_view or
                        _security.post_login_view)

    return render_template('security/registrations/new.html',
                           register_user_form=form)


def send_confirmation():
    form = ResendConfirmationForm()

    if form.validate_on_submit():
        user = _datastore.find_user(email=form.email.data)

        reset_confirmation_token(user)

        _logger.debug('%s request confirmation instructions' % user)

        msg = 'A new confirmation code has been sent to ' + user.email
        do_flash(msg, 'info')

    else:
        for key, value in form.errors.items():
            do_flash(value[0], 'error')

    return render_template('security/confirmations/new.html',
                           reset_confirmation_form=form)


def confirm_account(token):
    """View function which handles a account confirmation request."""
    error = False

    try:
        user = confirm_by_token(token)

    except ConfirmationError, e:
        error = True

        _logger.debug('Confirmation error: ' + str(e))

        do_flash(str(e), 'error')

    except TokenExpiredError, e:
        error = True

        reset_confirmation_token(e.user)

        msg = 'You did not confirm your email within %s. ' \
              'A new confirmation code has been sent to %s' % (
               _security.confirm_email_within, e.user.email)

        _logger.debug('Attempted account confirmation but token was expired')

        do_flash(msg, 'error')

    if error:
        return redirect(get_url(_security.confirm_error_view))

    _logger.debug('User %s confirmed' % user)

    do_flash('Your email has been confirmed. You may now log in.', 'success')

    return redirect(_security.post_confirm_view or
                    _security.post_login_view)


def forgot_password():
    """View function that handles a forgotten password request."""

    form = ForgotPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        user = _datastore.find_user(**form.to_dict())

        reset_password_reset_token(user)

        _logger.debug('%s requested to reset their password' % user)

        do_flash('Instructions to reset your password have been '
                 'sent to %s' % user.email, 'success')

        return redirect(_security.post_forgot_view)

    else:
        _logger.debug('A reset password request was made for %s but '
                      'that email does not exist.' % form.email.data)

        for key, value in form.errors.items():
            do_flash(value[0], 'error')

    return render_template('security/passwords/new.html',
                           forgot_password_form=form)


def reset_password(token):
    """View function that handles a reset password request."""

    form = ResetPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        try:
            reset_by_token(token=token, **form.to_dict())

        except ResetPasswordError, e:
            _logger.debug('Password reset error: ' + str(e))

            do_flash(str(e), 'error')

        except TokenExpiredError, e:
            _logger.debug('Attempted password reset but token was expired')

            do_flash('You did not reset your password within '
                     '%s.' % _security.reset_password_within)

    return render_template('security/passwords/edit.html',
                           reset_password_form=form,
                           password_reset_token=token)
