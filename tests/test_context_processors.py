# -*- coding: utf-8 -*-
"""
    test_context_processors
    ~~~~~~~~~~~~~~~~~~~~~~~

    Context processor tests
"""

from utils import authenticate, init_app_with_options


def test_context_processors(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_RECOVERABLE': True,
        # 'SECURITY_PASSWORDLESS': True,
        'SECURITY_REGISTERABLE': True,
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_CHANGEABLE': True,
        'SECURITY_LOGIN_WITHOUT_CONFIRMATION': True,
        'SECURITY_CHANGE_PASSWORD_TEMPLATE': 'custom_security/change_password.html',
        'SECURITY_LOGIN_USER_TEMPLATE': 'custom_security/login_user.html',
        # 'SECURITY_SEND_LOGIN_TEMPLATE': 'custom_security/send_login.html',
        'SECURITY_RESET_PASSWORD_TEMPLATE': 'custom_security/reset_password.html',
        'SECURITY_FORGOT_PASSWORD_TEMPLATE': 'custom_security/forgot_password.html',
        'SECURITY_SEND_CONFIRMATION_TEMPLATE': 'custom_security/send_confirmation.html',
        'SECURITY_REGISTER_USER_TEMPLATE': 'custom_security/register_user.html'
    })

    client = app.test_client()

    @app.security.forgot_password_context_processor
    def forgot_password():
        return {'foo': 'bar'}

    response = client.get('/reset')
    assert b'bar' in response.data

    @app.security.login_context_processor
    def login():
        return {'foo': 'bar'}

    response = client.get('/login')
    assert b'bar' in response.data

    @app.security.register_context_processor
    def register():
        return {'foo': 'bar'}

    response = client.get('/register')
    assert b'bar' in response.data

    @app.security.reset_password_context_processor
    def reset_password():
        return {'foo': 'bar'}

    response = client.get('/reset')
    assert b'bar' in response.data

    @app.security.change_password_context_processor
    def change_password():
        return {'foo': 'bar'}

    authenticate(client)
    response = client.get('/change')
    assert b'bar' in response.data

    @app.security.send_confirmation_context_processor
    def send_confirmation():
        return {'foo': 'bar'}

    response = client.get('/confirm')
    assert b'bar' in response.data

    @app.security.mail_context_processor
    def mail():
        return {'foo': 'bar'}

    with app.mail.record_messages() as outbox:
        client.post('/reset', data=dict(email='matt@lp.com'))

    email = outbox[0]
    assert b'bar' in email.html


def test_passwordless_login_context_processor(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_PASSWORDLESS': True,
        'SECURITY_SEND_LOGIN_TEMPLATE': 'custom_security/send_login.html',
    })

    client = app.test_client()

    @app.security.send_login_context_processor
    def send_login():
        return {'foo': 'bar'}

    response = client.get('/login')
    assert b'bar' in response.data

    # @app.security.mail_context_processor
    # def mail():
    #     return {'foo': 'bar'}




