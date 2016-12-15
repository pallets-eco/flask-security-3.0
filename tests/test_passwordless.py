# -*- coding: utf-8 -*-
"""
    test_passwordless
    ~~~~~~~~~~~~~~~~~

    Passwordless tests
"""

import time

import pytest
from flask import Flask
from utils import logout

from flask_security.core import UserMixin
from flask_security.signals import login_instructions_sent
from flask_security.utils import capture_passwordless_login_requests, \
    string_types

pytestmark = pytest.mark.passwordless()


def test_trackable_flag(app, client, get_message):
    recorded = []

    @login_instructions_sent.connect_via(app)
    def on_instructions_sent(app, user, login_token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert isinstance(login_token, string_types)
        recorded.append(user)

    # Test disabled account
    response = client.post(
        '/login',
        data=dict(
            email='tiya@lp.com'),
        follow_redirects=True)
    assert get_message('DISABLED_ACCOUNT') in response.data

    # Test login with json and valid email
    data = '{"email": "matt@lp.com", "password": "password"}'
    response = client.post(
        '/login',
        data=data,
        headers={
            'Content-Type': 'application/json'})
    assert response.status_code == 200
    assert len(recorded) == 1

    # Test login with json and invalid email
    data = '{"email": "nobody@lp.com", "password": "password"}'
    response = client.post(
        '/login',
        data=data,
        headers={
            'Content-Type': 'application/json'})
    assert b'errors' in response.data

    # Test sends email and shows appropriate response
    with capture_passwordless_login_requests() as requests:
        with app.mail.record_messages() as outbox:
            response = client.post(
                '/login',
                data=dict(
                    email='matt@lp.com'),
                follow_redirects=True)

    assert len(recorded) == 2
    assert len(requests) == 1
    assert len(outbox) == 1
    assert 'user' in requests[0]
    assert 'login_token' in requests[0]

    user = requests[0]['user']
    assert get_message('LOGIN_EMAIL_SENT', email=user.email) in response.data

    token = requests[0]['login_token']
    response = client.get('/login/' + token, follow_redirects=True)
    assert get_message('PASSWORDLESS_LOGIN_SUCCESSFUL') in response.data

    # Test already authenticated
    response = client.get('/login/' + token, follow_redirects=True)
    assert get_message('PASSWORDLESS_LOGIN_SUCCESSFUL') not in response.data

    logout(client)

    # Test invalid token
    response = client.get('/login/bogus', follow_redirects=True)
    assert get_message('INVALID_LOGIN_TOKEN') in response.data

    # Test login request with invalid email
    response = client.post('/login', data=dict(email='bogus@bogus.com'))
    assert get_message('USER_DOES_NOT_EXIST') in response.data


@pytest.mark.settings(login_within='1 milliseconds')
def test_expired_login_token(client, app, get_message):
    e = 'matt@lp.com'

    with capture_passwordless_login_requests() as requests:
        client.post('/login', data=dict(email=e), follow_redirects=True)

    token = requests[0]['login_token']
    user = requests[0]['user']

    time.sleep(1)

    response = client.get('/login/' + token, follow_redirects=True)
    assert get_message(
        'LOGIN_EXPIRED',
        within='1 milliseconds',
        email=user.email) in response.data
