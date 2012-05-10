# -*- coding: utf-8 -*-
"""
    flask.ext.security.views
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app, redirect, request, session
from flask.ext.login import login_user, logout_user
from flask.ext.principal import Identity, AnonymousIdentity, identity_changed
from flask.ext.security import exceptions, utils


def authenticate():
    try:
        form = current_app.security.form_class()
        user = current_app.security.auth_provider.authenticate(form)

        if login_user(user, remember=form.remember.data):
            redirect_url = utils.get_post_login_redirect()
            identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(user.id))
            current_app.logger.debug('User %s logged in. Redirecting to: '
                                     '%s' % (user, redirect_url))
            return redirect(redirect_url)

        raise exceptions.BadCredentialsError('Inactive user')

    except exceptions.BadCredentialsError, e:
        message = '%s' % e
        utils.do_flash(message, 'error')
        redirect_url = request.referrer or \
                       current_app.security.login_manager.login_view
        current_app.logger.error('Unsuccessful authentication attempt: %s. '
                                 'Redirect to: %s' % (message, redirect_url))
        return redirect(redirect_url)


def logout():
    for value in ('identity.name', 'identity.auth_type'):
        session.pop(value, None)

    identity_changed.send(current_app._get_current_object(),
                          identity=AnonymousIdentity())
    logout_user()

    redirect_url = utils.find_redirect('SECURITY_POST_LOGOUT_VIEW')
    current_app.logger.debug('User logged out. Redirect to: %s' % redirect_url)
    return redirect(redirect_url)


def reset():
    # user = something
    # if reset_password_period_valid_for_user(user):
    #     user.reset_password_sent_at = datetime.utcnow()
    #     user.reset_password_token = token
    #     current_app.security.datastore._save_model(user)
    pass
