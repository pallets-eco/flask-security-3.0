# -*- coding: utf-8 -*-
"""
    test_context_processors
    ~~~~~~~~~~~~~~~~~~~~~~~

    Context processor tests
"""

import pytest
from utils import authenticate


@pytest.mark.recoverable()
@pytest.mark.registerable()
@pytest.mark.confirmable()
@pytest.mark.changeable()
@pytest.mark.settings(
    login_without_confirmation=True,
    change_password_template='custom_security/change_password.html',
    login_user_template='custom_security/login_user.html',
    reset_password_template='custom_security/reset_password.html',
    forgot_password_template='custom_security/forgot_password.html',
    send_confirmation_template='custom_security/send_confirmation.html',
    register_user_template='custom_security/register_user.html')
def test_context_processors(client, app):
    @app.security.context_processor
    def default_ctx_processor():
        return {'global': 'global'}

    @app.security.forgot_password_context_processor
    def forgot_password():
        return {'foo': 'bar'}

    response = client.get('/reset')
    assert b'global' in response.data
    assert b'bar' in response.data

    @app.security.login_context_processor
    def login():
        return {'foo': 'bar'}

    response = client.get('/login')
    assert b'global' in response.data
    assert b'bar' in response.data

    @app.security.register_context_processor
    def register():
        return {'foo': 'bar'}

    response = client.get('/register')
    assert b'global' in response.data
    assert b'bar' in response.data

    @app.security.reset_password_context_processor
    def reset_password():
        return {'foo': 'bar'}

    response = client.get('/reset')
    assert b'global' in response.data
    assert b'bar' in response.data

    @app.security.change_password_context_processor
    def change_password():
        return {'foo': 'bar'}

    authenticate(client)
    response = client.get('/change')
    assert b'global' in response.data
    assert b'bar' in response.data

    @app.security.send_confirmation_context_processor
    def send_confirmation():
        return {'foo': 'bar'}

    response = client.get('/confirm')
    assert b'global' in response.data
    assert b'bar' in response.data

    @app.security.mail_context_processor
    def mail():
        return {'foo': 'bar'}

    client.get('/logout')

    with app.mail.record_messages() as outbox:
        client.post('/reset', data=dict(email='matt@lp.com'))

    email = outbox[0]
    assert 'global' in email.html
    assert 'bar' in email.html


@pytest.mark.passwordless()
@pytest.mark.settings(send_login_template='custom_security/send_login.html')
def test_passwordless_login_context_processor(app, client):
    @app.security.send_login_context_processor
    def send_login():
        return {'foo': 'bar'}

    response = client.get('/login')
    assert b'bar' in response.data
