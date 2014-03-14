# -*- coding: utf-8 -*-
"""
    test_registerable
    ~~~~~~~~~~~~~~~~~

    Registerable tests
"""

from flask_security.signals import user_registered

from utils import authenticate, logout, init_app_with_options


def _get_client(app, datastore, **options):
    config = {
        'SECURITY_REGISTERABLE': True,
        'SECURITY_POST_REGISTER_VIEW': '/post_register',
    }
    config.update(options)
    init_app_with_options(app, datastore, **config)
    return app.test_client()


def test_registerable_flag(app, sqlalchemy_datastore, get_message):
    client = _get_client(app, sqlalchemy_datastore)
    recorded = []

    # Test the register view
    response = client.get('/register')
    assert b"<h1>Register</h1>" in response.data

    # Test registering is successful, sends email, and fires signal
    @user_registered.connect_via(app)
    def on_user_registerd(app, user, confirm_token):
        recorded.append(user)

    data = dict(email='dude@lp.com', password='password', password_confirm='password')
    with app.mail.record_messages() as outbox:
        response = client.post('/register', data=data, follow_redirects=True)

    assert len(recorded) == 1
    assert len(outbox) == 1
    assert b'Post Register' in response.data

    logout(client)

    # Test user can login after registering
    response = authenticate(client, email='dude@lp.com', password='password')
    assert response.status_code == 302

    logout(client)

    # Test registering with an existing email
    data = dict(email='dude@lp.com', password='password', password_confirm='password')
    response = client.post('/register', data=data, follow_redirects=True)
    assert get_message('EMAIL_ALREADY_ASSOCIATED', email='dude@lp.com') in response.data

    # Test registering with JSON
    data = '{ "email": "dude2@lp.com", "password": "password"}'
    response = client.post('/register', data=data, headers={'Content-Type': 'application/json'})
    assert response.headers['content-type'] == 'application/json'
    assert response.jdata['meta']['code'] == 200

    logout(client)

    # Test registering with invalid JSON
    data = '{ "email": "bogus", "password": "password"}'
    response = client.post('/register', data=data, headers={'Content-Type': 'application/json'})
    print response.data
    assert response.headers['content-type'] == 'application/json'
    assert response.jdata['meta']['code'] == 400

    logout(client)

    # Test ?next param
    data = dict(email='dude3@lp.com',
                password='password',
                password_confirm='password')

    response = client.post('/register?next=/page1', data=data, follow_redirects=True)
    assert b'Page 1' in response.data


def test_custom_register_url(app, sqlalchemy_datastore):
    client = _get_client(app, sqlalchemy_datastore, **{
        'SECURITY_REGISTER_URL': '/custom_register'
    })

    response = client.get('/custom_register')
    assert b"<h1>Register</h1>" in response.data

    data = dict(email='dude@lp.com',
                password='password',
                password_confirm='password')

    response = client.post('/custom_register', data=data, follow_redirects=True)
    assert b'Post Register' in response.data


def test_custom_register_tempalate(app, sqlalchemy_datastore):
    client = _get_client(app, sqlalchemy_datastore, **{
        'SECURITY_REGISTER_USER_TEMPLATE': 'custom_security/register_user.html'
    })
    response = client.get('/register')
    assert b'CUSTOM REGISTER USER' in response.data


def test_disable_register_emails(app, sqlalchemy_datastore):
    client = _get_client(app, sqlalchemy_datastore, **{
        'SECURITY_SEND_REGISTER_EMAIL': False
    })
    data = dict(email='dude@lp.com', password='password', password_confirm='password')
    with app.mail.record_messages() as outbox:
        client.post('/register', data=data, follow_redirects=True)
    assert len(outbox) == 0
