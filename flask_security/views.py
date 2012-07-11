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
from .exceptions import TokenExpiredError, UserNotFoundError, \
     ConfirmationError, BadCredentialsError, ResetPasswordError
from .forms import LoginForm, RegisterForm, ForgotPasswordForm, \
     ResetPasswordForm
from .recoverable import reset_by_token, \
     reset_password_reset_token
from .signals import user_registered
from .tokens import generate_authentication_token
from .utils import get_post_login_redirect, do_flash, get_remember_token


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

    if request.json:
        return _json_auth_error(msg)

    do_flash(msg, 'error')
    _logger.debug('Unsuccessful authentication attempt: %s' % msg)

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


def register():
    """View function which handles a registration request."""

    form = RegisterForm(csrf_enabled=not app.testing)

    # Exit early if the form doesn't validate
    if form.validate_on_submit():
        # Create user and send signal
        user = _datastore.create_user(**form.to_dict())
        confirm_token = None

        # Send confirmation instructions if necessary
        if _security.confirmable:
            confirm_token = reset_confirmation_token(user)

        user_registered.send(dict(user=user, confirm_token=confirm_token),
                             app=app._get_current_object())

        _logger.debug('User %s registered' % user)

        # Login the user if allowed
        if not _security.confirmable or _security.login_without_confirmation:
            _do_login(user)

        return redirect(_security.post_register_view or
                        _security.post_login_view)

    return redirect(request.referrer or
                    _security.register_url)


def confirm(token):
    """View function which handles a account confirmation request."""

    try:
        user = confirm_by_token(token)

    except ConfirmationError, e:
        do_flash(str(e), 'error')
        return redirect('/')  # TODO: Don't just redirect to root

    except TokenExpiredError, e:
        reset_confirmation_token(e.user)

        msg = 'You did not confirm your email within %s. ' \
              'A new confirmation code has been sent to %s' % (
               _security.confirm_email_within, e.user.email)

        do_flash(msg, 'error')
        return redirect('/')  # TODO: Don't redirect to root

    _logger.debug('User %s confirmed' % user)
    do_flash('Your email has been confirmed. You may now log in.', 'success')

    return redirect(_security.post_confirm_view or
                    _security.post_login_view)


def forgot():
    """View function that handles a forgotten password request."""

    form = ForgotPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        try:
            user = _datastore.find_user(**form.to_dict())

            reset_password_reset_token(user)

            do_flash('Instructions to reset your password have been '
                     'sent to %s' % user.email, 'success')

        except UserNotFoundError:
            do_flash('The email you provided could not be found', 'error')

        return redirect(_security.post_forgot_view)

    return render_template('security/passwords/new.html',
                           forgot_password_form=form)


def reset(token):
    """View function that handles a reset password request."""

    form = ResetPasswordForm(csrf_enabled=not app.testing)

    if form.validate_on_submit():
        try:
            reset_by_token(token=token, **form.to_dict())

        except ResetPasswordError, e:
            do_flash(str(e), 'error')

        except TokenExpiredError, e:
            do_flash('You did not reset your password within'
                     '%s.' % _security.reset_password_within)

    return redirect(request.referrer or
                    _security.reset_password_error_view)
