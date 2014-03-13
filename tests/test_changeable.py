# -*- coding: utf-8 -*-
"""
    test_changeable
    ~~~~~~~~~~~~~~~

    Changeable tests
"""

from flask_security.signals import password_changed

from utils import authenticate, init_app_with_options


def _get_client(app, datastore, **options):
    config = {
        'SECURITY_CHANGEABLE': True
    }
    config.update(options)
    init_app_with_options(app, datastore, **config)
    return app.test_client()


def test_recoverable_flag(app, sqlalchemy_datastore, get_message):
    client = _get_client(app, sqlalchemy_datastore)

    recorded = []

    @password_changed.connect_via(app)
    def on_password_changed(app, user):
        recorded.append(user)

    authenticate(client)

    # Test change view
    response = client.get('/change', follow_redirects=True)
    assert b'Change password' in response.data

    # Test wrong original password
    response = client.post('/change', data={
        'password': 'notpassword',
        'new_password': 'newpassword',
        'new_password_confirm': 'newpassword'
    }, follow_redirects=True)
    assert get_message('INVALID_PASSWORD') in response.data

    # Test mismatch
    response = client.post('/change', data={
        'password': 'password',
        'new_password': 'newpassword',
        'new_password_confirm': 'notnewpassword'
    }, follow_redirects=True)
    assert get_message('PASSWORD_CHANGE') not in response.data
    assert get_message('RETYPE_PASSWORD_MISMATCH') in response.data

    # Test bad password
    response = client.post('/change', data={
        'password': 'password',
        'new_password': 'a',
        'new_password_confirm': 'a'
    }, follow_redirects=True)
    assert get_message('PASSWORD_CHANGE') not in response.data
    assert get_message('PASSWORD_INVALID_LENGTH') in response.data

    # Test same as previous
    response = client.post('/change', data={
        'password': 'password',
        'new_password': 'password',
        'new_password_confirm': 'password'
    }, follow_redirects=True)
    assert get_message('PASSWORD_CHANGE') not in response.data
    assert get_message('PASSWORD_IS_THE_SAME') in response.data

    # Test successful submit sends email notification
    with app.mail.record_messages() as outbox:
        response = client.post('/change', data={
            'password': 'password',
            'new_password': 'newpassword',
            'new_password_confirm': 'newpassword'
        }, follow_redirects=True)

    assert get_message('PASSWORD_CHANGE') in response.data
    assert b'Home Page' in response.data
    assert len(recorded) == 1
    assert len(outbox) == 1
    assert "Your password has been changed" in outbox[0].html


def test_custom_change_url(app, sqlalchemy_datastore, get_message):
    client = _get_client(app, sqlalchemy_datastore, **{
        'SECURITY_CHANGE_URL': '/custom_change'
    })

    authenticate(client)
    response = client.get('/custom_change')
    assert response.status_code == 200


def test_custom_change_template(app, sqlalchemy_datastore, get_message):
    client = _get_client(app, sqlalchemy_datastore, **{
        'SECURITY_CHANGE_PASSWORD_TEMPLATE': 'custom_security/change_password.html'
    })

    authenticate(client)
    response = client.get('/change')
    assert b'CUSTOM CHANGE PASSWORD' in response.data


def test_disable_change_emails(app, sqlalchemy_datastore):
    client = _get_client(app, sqlalchemy_datastore, **{
        'SECURITY_SEND_PASSWORD_CHANGE_EMAIL': False
    })
    authenticate(client)

    with app.mail.record_messages() as outbox:
        client.post('/change', data={
            'password': 'password',
            'new_password': 'newpassword',
            'new_password_confirm': 'newpassword'
        }, follow_redirects=True)
    assert len(outbox) == 0


def test_custom_post_change_view(app, sqlalchemy_datastore):
    client = _get_client(app, sqlalchemy_datastore, **{
        'SECURITY_POST_CHANGE_VIEW': '/profile',
    })
    authenticate(client)

    response = client.post('/change', data={
        'password': 'password',
        'new_password': 'newpassword',
        'new_password_confirm': 'newpassword'
    }, follow_redirects=True)

    assert b'Profile Page' in response.data
