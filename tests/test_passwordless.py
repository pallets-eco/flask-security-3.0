# -*- coding: utf-8 -*-
"""
    test_passwordless
    ~~~~~~~~~~~~~~~~~

    Passwordless tests
"""

import time
import json

import pytest

from flask import Flask
from flask_security.core import UserMixin
from flask_security.signals import login_instructions_sent
from flask_security.utils import capture_passwordless_login_requests, string_types

from utils import logout

pytestmark = pytest.mark.passwordless()

@pytest.fixture()
def instructions_sent(app):
    recorded = []

    @login_instructions_sent.connect_via(app)
    def on_instructions_sent(app, user, login_token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert isinstance(login_token, string_types)
        recorded.append(user)
    return recorded


def test_disabled_count(app, client, get_message):
    response = client.post('/login', data=dict(email='tiya@lp.com'), follow_redirects=True)
    assert get_message('DISABLED_ACCOUNT') in response.data

def test_valid_json_login_existing_user(app, client, get_message, instructions_sent):
    data = '{"email": "matt@lp.com", "password": "password"}'
    response = client.post('/login', data=data, headers={'Content-Type': 'application/json'})
    assert response.status_code == 200
    assert len(instructions_sent) == 1

'''
def test_valid_json_login_new_user(app, client, get_message, instructions_sent):
    data = '{"email": "nobody@lp.com", "password": "password"}'
    response = client.post('/login', data=data, headers={'Content-Type': 'application/json'})
    assert response.status_code == 200
    assert len(instructions_sent) == 1
'''

def test_trackable_flag(app, client, get_message, instructions_sent):
    # Test sends email and shows appropriate response
    with capture_passwordless_login_requests() as requests:
        with app.mail.record_messages() as outbox:
            response = client.post('/login', data=dict(email='matt@lp.com'),
                                   follow_redirects=True)

    assert len(instructions_sent) == 1
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

    # Test json based login
    response = client.get('/login/' + token,
                          headers=dict(Accept="application/json"))
    assert 'next' in response.data
    response_user = json.loads(response.data)['response']['user']
    assert 'authentication_token' in response_user
    assert response_user['authentication_token'] != token

    logout(client)


def test_invalid_login_token(app, client, get_message):
    response = client.get('/login/bogus', follow_redirects=True)
    assert get_message('INVALID_LOGIN_TOKEN') in response.data


def test_invalid_login_token_json(app, client, get_message):
    # Test json based failed login
    response = client.get('/login/bogus',
                          headers=dict(Accept="application/json"))
    assert get_message('INVALID_LOGIN_TOKEN') in response.data


@pytest.mark.settings(login_within='1 milliseconds')
def test_expired_login_token(client, app, get_message):
    e = 'matt@lp.com'

    with capture_passwordless_login_requests() as requests:
        client.post('/login', data=dict(email=e), follow_redirects=True)

    token = requests[0]['login_token']
    user = requests[0]['user']

    time.sleep(1)

    response = client.get('/login/' + token, follow_redirects=True)
    assert get_message('LOGIN_EXPIRED', within='1 milliseconds', email=user.email) in response.data
