# -*- coding: utf-8 -*-
"""
    test_confirmable
    ~~~~~~~~~~~~~~~~

    Confirmable tests
"""

import time

import pytest
from flask import Flask
from utils import authenticate, logout

from flask_security.core import UserMixin
from flask_security.confirmable import generate_confirmation_token
from flask_security.signals import confirm_instructions_sent, user_confirmed
from flask_security.utils import capture_registrations, string_types

pytestmark = pytest.mark.confirmable()


@pytest.mark.registerable()
def test_confirmable_flag(app, client, sqlalchemy_datastore, get_message):
    recorded_confirms = []
    recorded_instructions_sent = []

    @user_confirmed.connect_via(app)
    def on_confirmed(app, user):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        recorded_confirms.append(user)

    @confirm_instructions_sent.connect_via(app)
    def on_instructions_sent(app, user, token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert isinstance(token, string_types)
        recorded_instructions_sent.append(user)

    # Test login before confirmation
    email = 'dude@lp.com'

    with capture_registrations() as registrations:
        data = dict(email=email, password='password', next='')
        response = client.post('/register', data=data)

    assert response.status_code == 302

    response = authenticate(client, email=email)
    assert get_message('CONFIRMATION_REQUIRED') in response.data

    # Test invalid token
    response = client.get('/confirm/bogus', follow_redirects=True)
    assert get_message('INVALID_CONFIRMATION_TOKEN') in response.data

    # Test JSON
    response = client.post(
        '/confirm',
        data='{"email": "matt@lp.com"}',
        headers={
            'Content-Type': 'application/json'})
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json'
    assert 'user' in response.jdata['response']
    assert len(recorded_instructions_sent) == 1

    # Test ask for instructions with invalid email
    response = client.post('/confirm', data=dict(email='bogus@bogus.com'))
    assert get_message('USER_DOES_NOT_EXIST') in response.data

    # Test resend instructions
    response = client.post('/confirm', data=dict(email=email))
    assert get_message('CONFIRMATION_REQUEST', email=email) in response.data
    assert len(recorded_instructions_sent) == 2

    # Test confirm
    token = registrations[0]['confirm_token']
    response = client.get('/confirm/' + token, follow_redirects=True)
    assert get_message('EMAIL_CONFIRMED') in response.data
    assert len(recorded_confirms) == 1

    # Test already confirmed
    response = client.get('/confirm/' + token, follow_redirects=True)
    assert get_message('ALREADY_CONFIRMED') in response.data
    assert len(recorded_instructions_sent) == 2

    # Test already confirmed and expired token
    app.config['SECURITY_CONFIRM_EMAIL_WITHIN'] = '-1 days'
    with app.app_context():
        user = registrations[0]['user']
        expired_token = generate_confirmation_token(user)
    response = client.get('/confirm/' + expired_token, follow_redirects=True)
    assert get_message('ALREADY_CONFIRMED') in response.data
    assert len(recorded_instructions_sent) == 2

    # Test already confirmed when asking for confirmation instructions
    logout(client)

    response = client.get('/confirm')
    assert response.status_code == 200

    response = client.post('/confirm', data=dict(email=email))
    assert get_message('ALREADY_CONFIRMED') in response.data

    # Test user was deleted before confirmation
    with capture_registrations() as registrations:
        data = dict(email='mary@lp.com', password='password', next='')
        client.post('/register', data=data)

    user = registrations[0]['user']
    token = registrations[0]['confirm_token']

    with app.app_context():
        sqlalchemy_datastore.delete(user)
        sqlalchemy_datastore.commit()

    response = client.get('/confirm/' + token, follow_redirects=True)
    assert get_message('INVALID_CONFIRMATION_TOKEN') in response.data


@pytest.mark.registerable()
@pytest.mark.settings(confirm_email_within='1 milliseconds')
def test_expired_confirmation_token(client, get_message):
    with capture_registrations() as registrations:
        data = dict(email='mary@lp.com', password='password', next='')
        client.post('/register', data=data, follow_redirects=True)

    user = registrations[0]['user']
    token = registrations[0]['confirm_token']

    time.sleep(1)

    response = client.get('/confirm/' + token, follow_redirects=True)
    msg = get_message(
        'CONFIRMATION_EXPIRED',
        within='1 milliseconds',
        email=user.email)
    assert msg in response.data


@pytest.mark.registerable()
def test_email_conflict_for_confirmation_token(app, client, get_message,
                                               sqlalchemy_datastore):
    with capture_registrations() as registrations:
        data = dict(email='mary@lp.com', password='password', next='')
        client.post('/register', data=data, follow_redirects=True)

    user = registrations[0]['user']
    token = registrations[0]['confirm_token']

    # Change the user's email
    user.email = 'tom@lp.com'
    with app.app_context():
        sqlalchemy_datastore.put(user)
        sqlalchemy_datastore.commit()

    response = client.get('/confirm/' + token, follow_redirects=True)
    msg = get_message('INVALID_CONFIRMATION_TOKEN')
    assert msg in response.data


@pytest.mark.registerable()
@pytest.mark.settings(login_without_confirmation=True)
def test_login_when_unconfirmed(client, get_message):
    data = dict(email='mary@lp.com', password='password', next='')
    response = client.post('/register', data=data, follow_redirects=True)
    assert b'mary@lp.com' in response.data


@pytest.mark.registerable()
@pytest.mark.settings(login_without_confirmation=True)
def test_confirmation_different_user_when_logged_in(client, get_message):
    e1 = 'dude@lp.com'
    e2 = 'lady@lp.com'

    with capture_registrations() as registrations:
        for e in e1, e2:
            data = dict(email=e, password='password', next='')
            client.post('/register', data=data)
            logout(client)

    token1 = registrations[0]['confirm_token']
    token2 = registrations[1]['confirm_token']

    client.get('/confirm/' + token1, follow_redirects=True)
    logout(client)
    authenticate(client, email=e1)

    response = client.get('/confirm/' + token2, follow_redirects=True)
    assert get_message('EMAIL_CONFIRMED') in response.data
    assert b'Hello lady@lp.com' in response.data


@pytest.mark.registerable()
@pytest.mark.settings(recoverable=True)
def test_cannot_reset_password_when_email_is_not_confirmed(
        client,
        get_message):
    email = 'dude@lp.com'

    data = dict(email=email, password='password', next='')
    response = client.post('/register', data=data, follow_redirects=True)

    response = client.post(
        '/reset',
        data=dict(
            email=email),
        follow_redirects=True)
    assert get_message('CONFIRMATION_REQUIRED') in response.data
