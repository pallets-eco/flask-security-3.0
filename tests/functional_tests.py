# -*- coding: utf-8 -*-

from __future__ import with_statement

import base64
import time

try:
    import simplejson as json
except ImportError:
    import json

from flask.ext.security.utils import capture_registrations, \
     capture_reset_password_requests

from example import app
from tests import SecurityTest


class DefaultSecurityTests(SecurityTest):

    def test_login_view(self):
        r = self._get('/login')
        self.assertIn('Login Page', r.data)

    def test_authenticate(self):
        r = self.authenticate()
        self.assertIn('Hello matt@lp.com', r.data)

    def test_unprovided_username(self):
        r = self.authenticate("")
        self.assertIn("Email not provided", r.data)

    def test_unprovided_password(self):
        r = self.authenticate(password="")
        self.assertIn("Password not provided", r.data)

    def test_invalid_email(self):
        r = self.authenticate(email="bogus")
        self.assertIn("Invalid email address", r.data)

    def test_invalid_user(self):
        r = self.authenticate(email="bogus@bogus.com")
        self.assertIn("Specified user does not exist", r.data)

    def test_bad_password(self):
        r = self.authenticate(password="bogus")
        self.assertIn("Password does not match", r.data)

    def test_inactive_user(self):
        r = self.authenticate("tiya@lp.com", "password")
        self.assertIn("Account is disabled", r.data)

    def test_logout(self):
        self.authenticate()
        r = self.logout()
        self.assertIsHomePage(r.data)

    def test_unauthorized_access(self):
        r = self._get('/profile', follow_redirects=True)
        self.assertIn('Please log in to access this page', r.data)

    def test_authorized_access(self):
        self.authenticate()
        r = self._get("/profile")
        self.assertIn('profile', r.data)

    def test_valid_admin_role(self):
        self.authenticate()
        r = self._get("/admin")
        self.assertIn('Admin Page', r.data)

    def test_invalid_admin_role(self):
        self.authenticate("joe@lp.com")
        r = self._get("/admin", follow_redirects=True)
        self.assertIsHomePage(r.data)

    def test_roles_accepted(self):
        for user in ("matt@lp.com", "joe@lp.com"):
            self.authenticate(user)
            r = self._get("/admin_or_editor")
            self.assertIn('Admin or Editor Page', r.data)
            self.logout()

        self.authenticate("jill@lp.com")
        r = self._get("/admin_or_editor", follow_redirects=True)
        self.assertIsHomePage(r.data)

    def test_unauthenticated_role_required(self):
        r = self._get('/admin', follow_redirects=True)
        self.assertIn('<input id="next"', r.data)

    def test_multiple_role_required(self):
        for user in ("matt@lp.com", "joe@lp.com"):
            self.authenticate(user)
            r = self._get("/admin_and_editor", follow_redirects=True)
            self.assertIsHomePage(r.data)

        self.authenticate('dave@lp.com')
        r = self._get("/admin_and_editor")
        self.assertIn('Admin and Editor Page', r.data)

    def test_ok_json_auth(self):
        r = self.json_authenticate()
        self.assertIn('"code": 200', r.data)

    def test_invalid_json_auth(self):
        r = self.json_authenticate(password='junk')
        self.assertIn('"code": 400', r.data)

    def test_token_auth_via_querystring_valid_token(self):
        r = self.json_authenticate()
        data = json.loads(r.data)
        token = data['response']['user']['authentication_token']
        r = self._get('/token?auth_token=' + token)
        self.assertIn('Token Authentication', r.data)

    def test_token_auth_via_header_valid_token(self):
        r = self.json_authenticate()
        data = json.loads(r.data)
        token = data['response']['user']['authentication_token']
        headers = {"X-Auth-Token": token}
        r = self._get('/token', headers=headers)
        self.assertIn('Token Authentication', r.data)

    def test_token_auth_via_querystring_invalid_token(self):
        r = self._get('/token?auth_token=X')
        self.assertEqual(401, r.status_code)

    def test_token_auth_via_header_invalid_token(self):
        r = self._get('/token', headers={"X-Auth-Token": 'X'})
        self.assertEqual(401, r.status_code)

    def test_http_auth(self):
        r = self._get('/http', headers={
            'Authorization': 'Basic ' + base64.b64encode("joe@lp.com:password")
        })
        self.assertIn('HTTP Authentication', r.data)

    def test_invalid_http_auth(self):
        r = self._get('/http', headers={
            'Authorization': 'Basic ' + base64.b64encode("joe@lp.com:bogus")
        })
        self.assertIn('<h1>Unauthorized</h1>', r.data)
        self.assertIn('WWW-Authenticate', r.headers)
        self.assertEquals('Basic realm="Login Required"', r.headers['WWW-Authenticate'])

    def test_custom_http_auth_realm(self):
        r = self._get('/http_custom_realm', headers={
            'Authorization': 'Basic ' + base64.b64encode("joe@lp.com:bogus")
        })
        self.assertIn('<h1>Unauthorized</h1>', r.data)
        self.assertIn('WWW-Authenticate', r.headers)
        self.assertEquals('Basic realm="My Realm"', r.headers['WWW-Authenticate'])


class ConfiguredSecurityTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_REGISTERABLE': True,
        'SECURITY_AUTH_URL': '/custom_auth',
        'SECURITY_LOGOUT_URL': '/custom_logout',
        'SECURITY_LOGIN_VIEW': '/custom_login',
        'SECURITY_POST_LOGIN_VIEW': '/post_login',
        'SECURITY_POST_LOGOUT_VIEW': '/post_logout',
        'SECURITY_POST_REGISTER_VIEW': '/post_register',
        'SECURITY_UNAUTHORIZED_VIEW': '/unauthorized',
        'SECURITY_DEFAULT_HTTP_AUTH_REALM': 'Custom Realm'
    }

    def test_login_view(self):
        r = self._get('/custom_login')
        self.assertIn("Custom Login Page", r.data)

    def test_authenticate(self):
        r = self.authenticate(endpoint="/custom_auth")
        self.assertIn('Post Login', r.data)

    def test_logout(self):
        self.authenticate(endpoint="/custom_auth")
        r = self.logout(endpoint="/custom_logout")
        self.assertIn('Post Logout', r.data)

    def test_register(self):
        data = dict(email='dude@lp.com',
                    password='password',
                    password_confirm='password')

        r = self.client.post('/register', data=data, follow_redirects=True)
        self.assertIn('Post Register', r.data)

    def test_unauthorized(self):
        self.authenticate("joe@lp.com", endpoint="/custom_auth")
        r = self._get("/admin", follow_redirects=True)
        msg = 'You are not allowed to access the requested resouce'
        self.assertIn(msg, r.data)

    def test_default_http_auth_realm(self):
        r = self._get('/http', headers={
            'Authorization': 'Basic ' + base64.b64encode("joe@lp.com:bogus")
        })
        self.assertIn('<h1>Unauthorized</h1>', r.data)
        self.assertIn('WWW-Authenticate', r.headers)
        self.assertEquals('Basic realm="Custom Realm"', r.headers['WWW-Authenticate'])


class RegisterableTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_REGISTERABLE': True
    }

    def test_register_valid_user(self):
        data = dict(email='dude@lp.com', password='password', password_confirm='password')
        self.client.post('/register', data=data, follow_redirects=True)
        r = self.authenticate('dude@lp.com')
        self.assertIn('Hello dude@lp.com', r.data)


class ConfirmableTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_REGISTERABLE': True
    }

    def test_register_sends_confirmation_email(self):
        e = 'dude@lp.com'
        with self.app.mail.record_messages() as outbox:
            self.register(e)
            self.assertEqual(len(outbox), 1)
            self.assertIn(e, outbox[0].html)

    def test_confirm_email(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            token = registrations[0]['confirm_token']

        r = self.client.get('/confirm/' + token, follow_redirects=True)
        self.assertIn('Your account has been confirmed. You may now log in.', r.data)

    def test_confirm_email_twice_flashes_already_confirmed_message(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            token = registrations[0]['confirm_token']

        url = '/confirm/' + token
        self.client.get(url, follow_redirects=True)
        r = self.client.get(url, follow_redirects=True)
        self.assertIn('Your account has already been confirmed', r.data)

    def test_invalid_token_when_confirming_email(self):
        r = self.client.get('/confirm/bogus', follow_redirects=True)
        self.assertIn('Invalid confirmation token', r.data)


class ExpiredConfirmationTest(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_REGISTERABLE': True,
        'SECURITY_CONFIRM_EMAIL_WITHIN': '1 seconds'
    }

    def test_expired_confirmation_token_sends_email(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            token = registrations[0]['confirm_token']

        time.sleep(3)

        with self.app.mail.record_messages() as outbox:
            r = self.client.get('/confirm/' + token, follow_redirects=True)

            self.assertEqual(len(outbox), 1)
            self.assertIn(e, outbox[0].html)
            self.assertNotIn(token, outbox[0].html)

            expire_text = self.app.security.confirm_email_within
            text = 'You did not confirm your account within %s' % expire_text

            self.assertIn(text, r.data)


class LoginWithoutImmediateConfirmTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_REGISTERABLE': True,
        'SECURITY_LOGIN_WITHOUT_CONFIRMATION': True
    }

    def test_register_valid_user_automatically_signs_in(self):
        e = 'dude@lp.com'
        p = 'password'
        data = dict(email=e, password=p, password_confirm=p)
        r = self.client.post('/register', data=data, follow_redirects=True)
        self.assertIn(e, r.data)


class RecoverableTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
    }

    def test_forgot_post_sends_email(self):
        with capture_reset_password_requests():
            with self.app.mail.record_messages() as outbox:
                self.client.post('/reset', data=dict(email='joe@lp.com'))
                self.assertEqual(len(outbox), 1)

    def test_forgot_password_invalid_email(self):
        r = self.client.post('/reset',
                             data=dict(email='larry@lp.com'),
                             follow_redirects=True)
        self.assertIn('Invalid email address', r.data)

    def test_reset_password_with_valid_token(self):
        with capture_reset_password_requests() as requests:
            r = self.client.post('/reset',
                                 data=dict(email='joe@lp.com'),
                                 follow_redirects=True)
            t = requests[0]['token']

        r = self.client.post('/reset/' + t, data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)

        r = self.authenticate('joe@lp.com', 'newpassword')
        self.assertIn('Hello joe@lp.com', r.data)

    def test_reset_password_twice_flashes_invalid_token_msg(self):
        with capture_reset_password_requests() as requests:
            self.client.post('/reset', data=dict(email='joe@lp.com'))
            t = requests[0]['token']

        data = {
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }

        url = '/reset/' + t
        r = self.client.post(url, data=data, follow_redirects=True)
        r = self.client.post(url, data=data, follow_redirects=True)
        self.assertIn('Invalid reset password token', r.data)


class ExpiredResetPasswordTest(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
        'SECURITY_RESET_PASSWORD_WITHIN': '1 seconds'
    }

    def test_reset_password_with_expired_token(self):
        with capture_reset_password_requests() as requests:
            r = self.client.post('/reset',
                                 data=dict(email='joe@lp.com'),
                                 follow_redirects=True)
            t = requests[0]['token']

        time.sleep(2)

        r = self.client.post('/reset/' + t, data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)

        self.assertIn('You did not reset your password within', r.data)


class MongoEngineSecurityTests(DefaultSecurityTests):

    def _create_app(self, auth_config):
        return app.create_mongoengine_app(auth_config)
