# -*- coding: utf-8 -*-
"""
    test_recoverable
    ~~~~~~~~~~~~~~~~

    Recoverable functionality tests
"""

import time

import pytest

from flask_security.signals import reset_password_instructions_sent, password_reset
from flask_security.utils import capture_reset_password_requests

from utils import authenticate, logout

pytestmark = pytest.mark.recoverable()


def test_recoverable_flag(app, client, get_message):
    recorded_resets = []
    recorded_instructions_sent = []

    @password_reset.connect_via(app)
    def on_password_reset(app, user):
        recorded_resets.append(user)

    @reset_password_instructions_sent.connect_via(app)
    def on_instructions_sent(app, user, token):
        recorded_instructions_sent.append(user)

    # Test the reset view
    response = client.get('/reset')
    assert b'<h1>Send password reset instructions</h1>' in response.data

    # Test submitting email to reset password creates a token and sends email
    with capture_reset_password_requests() as requests:
        with app.mail.record_messages() as outbox:
            response = client.post('/reset', data=dict(email='joe@lp.com'), follow_redirects=True)

    assert len(recorded_instructions_sent) == 1
    assert len(outbox) == 1
    assert response.status_code == 200
    assert get_message('PASSWORD_RESET_REQUEST', email='joe@lp.com') in response.data
    token = requests[0]['token']

    # Test view for reset token
    response = client.get('/reset/' + token)
    assert b'<h1>Reset password</h1>' in response.data

    # Test submitting a new password
    response = client.post('/reset/' + token, data={
        'password': 'newpassword',
        'password_confirm': 'newpassword'
    }, follow_redirects=True)

    assert get_message('PASSWORD_RESET') in response.data
    assert len(recorded_resets) == 1

    logout(client)

    # Test logging in with the new password
    response = authenticate(client, 'joe@lp.com', 'newpassword', follow_redirects=True)
    assert b'Hello joe@lp.com' in response.data

    logout(client)

    # Test submitting JSON
    response = client.post('/reset', data='{"email": "joe@lp.com"}', headers={
        'Content-Type': 'application/json'
    })
    assert response.headers['Content-Type'] == 'application/json'
    assert 'user' not in response.jdata['response']

    logout(client)

    # Test invalid email
    response = client.post('/reset', data=dict(email='bogus@lp.com'), follow_redirects=True)
    assert get_message('USER_DOES_NOT_EXIST') in response.data

    logout(client)

    # Test invalid token
    response = client.post('/reset/bogus', data={
        'password': 'newpassword',
        'password_confirm': 'newpassword'
    }, follow_redirects=True)
    assert get_message('INVALID_RESET_PASSWORD_TOKEN') in response.data

    # Test mangled token
    token = ("WyIxNjQ2MzYiLCIxMzQ1YzBlZmVhM2VhZjYwODgwMDhhZGU2YzU0MzZjMiJd.BZEw_Q.lQyo3npdPZtcJ"
             "_sNHVHP103syjM&url_id=fbb89a8328e58c181ea7d064c2987874bc54a23d")
    response = client.post('/reset/' + token, data={
        'password': 'newpassword',
        'password_confirm': 'newpassword'
    }, follow_redirects=True)
    assert get_message('INVALID_RESET_PASSWORD_TOKEN') in response.data


@pytest.mark.settings(reset_password_within='1 milliseconds')
def test_expired_reset_token(client, get_message):
    with capture_reset_password_requests() as requests:
        client.post('/reset', data=dict(email='joe@lp.com'), follow_redirects=True)

    user = requests[0]['user']
    token = requests[0]['token']

    time.sleep(1)

    response = client.post('/reset/' + token, data={
        'password': 'newpassword',
        'password_confirm': 'newpassword'
    }, follow_redirects=True)

    msg = get_message('PASSWORD_RESET_EXPIRED', within='1 milliseconds', email=user.email)
    assert msg in response.data


@pytest.mark.settings(reset_url='/custom_reset')
def test_custom_reset_url(client):
    response = client.get('/custom_reset')
    assert response.status_code == 200


@pytest.mark.settings(reset_password_template='custom_security/reset_password.html',
                      forgot_password_template='custom_security/forgot_password.html')
def test_custom_reset_templates(client):
    response = client.get('/reset')
    assert b'CUSTOM FORGOT PASSWORD' in response.data

    with capture_reset_password_requests() as requests:
        client.post('/reset', data=dict(email='joe@lp.com'), follow_redirects=True)
        token = requests[0]['token']

    response = client.get('/reset/' + token)
    assert b'CUSTOM RESET PASSWORD' in response.data
