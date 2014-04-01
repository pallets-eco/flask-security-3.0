# -*- coding: utf-8 -*-
"""
    test_context_processors
    ~~~~~~~~~~~~~~~~~~~~~~~

    Context processor tests
"""

from utils import init_app_with_options
from flask_security.forms import LoginForm


def test_context_processor(app, sqlalchemy_datastore):
    class TestLoginForm(LoginForm):
        mname = 'test_macro'
        mtemplate = 'custom_security/macros/_test.html'

    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_RECOVERABLE': True,
        'SECURITY_LOGIN_TEMPLATE': 'custom_security/login_user.html',
        'SECURITY_RESET_PASSWORD_TEMPLATE': 'custom_security/reset_password.html',
        'security_args': {'login_form': TestLoginForm}
    })

    client = app.test_client()

    @app.security.add_ctx
    def login_ctxone():
        return {'foo': 'bar'}

    @app.security.add_ctx
    def login_ctxtwo():
        return {'bar': 'foo'}

    response = client.get('/login')
    assert b'foo' in response.data
    assert b'bar' in response.data

    @app.security.send_mail_task
    def test_mail_ctx(msg):
        return {'foo': 'bar'}

    with app.mail.record_messages() as outbox:
        client.post('/reset', data=dict(email='matt@lp.com'))

    email = outbox[0]
    assert b'bar' in email.html
