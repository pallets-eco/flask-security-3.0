# -*- coding: utf-8 -*-
"""
    test_configuration
    ~~~~~~~~~~~~~~~~~~

    Basic configuration tests
"""

import base64

from utils import authenticate, logout, init_app_with_options


def test_view_configuration(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_LOGOUT_URL': '/custom_logout',
        'SECURITY_LOGIN_URL': '/custom_login',
        'SECURITY_POST_LOGIN_VIEW': '/post_login',
        'SECURITY_POST_LOGOUT_VIEW': '/post_logout',
        'SECURITY_DEFAULT_HTTP_AUTH_REALM': 'Custom Realm',
    })

    client = app.test_client()

    response = client.get('/custom_login')
    assert b"<h1>Login</h1>" in response.data

    response = authenticate(client, endpoint='/custom_login', follow_redirects=True)
    assert b'Post Login' in response.data

    response = logout(client, endpoint='/custom_logout', follow_redirects=True)
    assert b'Post Logout' in response.data

    response = client.get('/http', headers={
        'Authorization': 'Basic %s' % base64.b64encode(b"joe@lp.com:bogus")
    })
    assert b'<h1>Unauthorized</h1>' in response.data
    assert 'WWW-Authenticate' in response.headers
    assert 'Basic realm="Custom Realm"' == response.headers['WWW-Authenticate']


def test_template_configuration(app, sqlalchemy_datastore):
    init_app_with_options(app, sqlalchemy_datastore, **{
        'SECURITY_LOGIN_USER_TEMPLATE': 'custom_security/login_user.html',
    })
    client = app.test_client()
    response = client.get('/login')
    assert b'CUSTOM LOGIN USER' in response.data
