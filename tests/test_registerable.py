# -*- coding: utf-8 -*-
"""
    test_registerable
    ~~~~~~~~~~~~~~~~~

    Registerable tests
"""

import pytest
from flask import Flask
from utils import authenticate, logout

from flask_security.core import UserMixin
from flask_security.signals import user_registered

pytestmark = pytest.mark.registerable()


@pytest.mark.settings(post_register_view='/post_register')
def test_registerable_flag(client, app, get_message):
    recorded = []

    # Test the register view
    response = client.get('/register')
    assert b"<h1>Register</h1>" in response.data

    # Test registering is successful, sends email, and fires signal
    @user_registered.connect_via(app)
    def on_user_registerd(app, user, confirm_token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert confirm_token is None
        recorded.append(user)

    data = dict(
        email='dude@lp.com', password='password', password_confirm='password',
        next=''
    )
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
    data = dict(
        email='dude@lp.com', password='password', password_confirm='password',
        next=''
    )
    response = client.post('/register', data=data, follow_redirects=True)
    assert get_message(
        'EMAIL_ALREADY_ASSOCIATED',
        email='dude@lp.com') in response.data

    # Test registering with an existing email but case insensitive
    data = dict(
        email='Dude@lp.com', password='password', password_confirm='password',
        next=''
    )
    response = client.post('/register', data=data, follow_redirects=True)
    assert get_message(
        'EMAIL_ALREADY_ASSOCIATED',
        email='Dude@lp.com') in response.data

    # Test registering with JSON
    data = '{ "email": "dude2@lp.com", "password": "password"}'
    response = client.post(
        '/register',
        data=data,
        headers={
            'Content-Type': 'application/json'})
    assert response.headers['content-type'] == 'application/json'
    assert response.jdata['meta']['code'] == 200

    logout(client)

    # Test registering with invalid JSON
    data = '{ "email": "bogus", "password": "password"}'
    response = client.post(
        '/register',
        data=data,
        headers={
            'Content-Type': 'application/json'})
    assert response.headers['content-type'] == 'application/json'
    assert response.jdata['meta']['code'] == 400

    logout(client)

    # Test ?next param
    data = dict(email='dude3@lp.com',
                password='password',
                password_confirm='password',
                next='')

    response = client.post(
        '/register?next=/page1',
        data=data,
        follow_redirects=True)
    assert b'Page 1' in response.data


@pytest.mark.settings(
    register_url='/custom_register',
    post_register_view='/post_register')
def test_custom_register_url(client):
    response = client.get('/custom_register')
    assert b"<h1>Register</h1>" in response.data

    data = dict(email='dude@lp.com',
                password='password',
                password_confirm='password',
                next='')

    response = client.post(
        '/custom_register',
        data=data,
        follow_redirects=True)
    assert b'Post Register' in response.data


@pytest.mark.settings(
    register_user_template='custom_security/register_user.html')
def test_custom_register_tempalate(client):
    response = client.get('/register')
    assert b'CUSTOM REGISTER USER' in response.data


@pytest.mark.settings(send_register_email=False)
def test_disable_register_emails(client, app):
    data = dict(
        email='dude@lp.com', password='password', password_confirm='password',
        next=''
    )
    with app.mail.record_messages() as outbox:
        client.post('/register', data=data, follow_redirects=True)
    assert len(outbox) == 0
