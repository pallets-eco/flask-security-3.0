# -*- coding: utf-8 -*-

from __future__ import with_statement

import base64
import time

from cookielib import Cookie

try:
    import simplejson as json
except ImportError:
    import json

from flask.ext.security.utils import capture_registrations, \
     capture_reset_password_requests, capture_passwordless_login_requests
from werkzeug.utils import parse_cookie

from tests import SecurityTest


def get_cookies(rv):
    cookies = {}
    for value in rv.headers.get_all("Set-Cookie"):
        cookies.update(parse_cookie(value))
    return cookies


class DefaultSecurityTests(SecurityTest):

    def test_instance(self):
        self.assertIsNotNone(self.app)
        self.assertIsNotNone(self.app.security)
        self.assertIsNotNone(self.app.security.pwd_context)

    def test_login_view(self):
        r = self._get('/login')
        self.assertIn('<h1>Login</h1>', r.data)

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
        self.assertIn(self.get_message('UNAUTHORIZED'), r.data)

    def test_multiple_role_required(self):
        for user in ("matt@lp.com", "joe@lp.com"):
            self.authenticate(user)
            r = self._get("/admin_and_editor", follow_redirects=True)
            self.assertIsHomePage(r.data)
            self._get('/logout')

        self.authenticate('dave@lp.com')
        r = self._get("/admin_and_editor", follow_redirects=True)
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
        headers = {"Authentication-Token": token}
        r = self._get('/token', headers=headers)
        self.assertIn('Token Authentication', r.data)

    def test_token_auth_via_querystring_invalid_token(self):
        r = self._get('/token?auth_token=X')
        self.assertEqual(401, r.status_code)

    def test_token_auth_via_header_invalid_token(self):
        r = self._get('/token', headers={"Authentication-Token": 'X'})
        self.assertEqual(401, r.status_code)

    def test_http_auth(self):
        r = self._get('/http', headers={
            'Authorization': 'Basic ' + base64.b64encode("joe@lp.com:password")
        })
        self.assertIn('HTTP Authentication', r.data)

    def test_invalid_http_auth_invalid_username(self):
        r = self._get('/http', headers={
            'Authorization': 'Basic ' + base64.b64encode("bogus:bogus")
        })
        self.assertIn('<h1>Unauthorized</h1>', r.data)
        self.assertIn('WWW-Authenticate', r.headers)
        self.assertEquals('Basic realm="Login Required"', r.headers['WWW-Authenticate'])

    def test_invalid_http_auth_bad_password(self):
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

    def test_user_deleted_during_session_reverts_to_anonymous_user(self):
        self.authenticate()

        with self.app.test_request_context('/'):
            user = self.app.security.datastore.find_user(email='matt@lp.com')
            self.app.security.datastore.delete_user(user)
            self.app.security.datastore._commit()

        r = self._get('/')
        self.assertNotIn('Hello matt@lp.com', r.data)

    def test_remember_token(self):
        r = self.authenticate(follow_redirects=False)
        self.client.cookie_jar.clear_session_cookies()
        r = self._get('/profile')
        self.assertIn('profile', r.data)

    def test_token_loader_does_not_fail_with_invalid_token(self):
        self.client.cookie_jar.set_cookie(Cookie(version=0, name='remember_token', value='None', port=None, port_specified=False, domain='www.example.com', domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False))
        r = self._get('/')
        self.assertNotIn('BadSignature', r.data)


class ConfiguredSecurityTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_HMAC_SALT': 'so-salty',
        'SECURITY_PASSWORD_HMAC': True,
        'SECURITY_REGISTERABLE': True,
        'SECURITY_LOGOUT_URL': '/custom_logout',
        'SECURITY_LOGIN_URL': '/custom_login',
        'SECURITY_POST_LOGIN_VIEW': '/post_login',
        'SECURITY_POST_LOGOUT_VIEW': '/post_logout',
        'SECURITY_POST_REGISTER_VIEW': '/post_register',
        'SECURITY_UNAUTHORIZED_VIEW': '/unauthorized',
        'SECURITY_DEFAULT_HTTP_AUTH_REALM': 'Custom Realm'
    }

    def test_login_view(self):
        r = self._get('/custom_login')
        self.assertIn("<h1>Login</h1>", r.data)

    def test_authenticate(self):
        r = self.authenticate(endpoint="/custom_login")
        self.assertIn('Post Login', r.data)

    def test_logout(self):
        self.authenticate(endpoint="/custom_login")
        r = self.logout(endpoint="/custom_logout")
        self.assertIn('Post Logout', r.data)

    def test_register_view(self):
        r = self._get('/register')
        self.assertIn('<h1>Register</h1>', r.data)

    def test_register(self):
        data = dict(email='dude@lp.com',
                    password='password',
                    password_confirm='password')

        r = self._post('/register', data=data, follow_redirects=True)
        self.assertIn('Post Register', r.data)

    def test_register_existing_email(self):
        data = dict(email='matt@lp.com',
                    password='password',
                    password_confirm='password')
        r = self._post('/register', data=data, follow_redirects=True)
        self.assertIn('matt@lp.com is already associated with an account', r.data)

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

    def test_login_before_confirmation(self):
        e = 'dude@lp.com'
        self.register(e)
        r = self.authenticate(email=e)
        self.assertIn(self.get_message('CONFIRMATION_REQUIRED'), r.data)

    def test_send_confirmation_of_already_confirmed_account(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            token = registrations[0]['confirm_token']

        self.client.get('/confirm/' + token, follow_redirects=True)
        self.logout()
        r = self.client.post('/confirm', data=dict(email=e))
        self.assertIn(self.get_message('ALREADY_CONFIRMED'), r.data)

    def test_register_sends_confirmation_email(self):
        e = 'dude@lp.com'
        with self.app.extensions['mail'].record_messages() as outbox:
            self.register(e)
            self.assertEqual(len(outbox), 1)
            self.assertIn(e, outbox[0].html)

    def test_confirm_email(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            token = registrations[0]['confirm_token']

        r = self.client.get('/confirm/' + token, follow_redirects=True)

        msg = self.app.config['SECURITY_MSG_EMAIL_CONFIRMED'][0]
        self.assertIn(msg, r.data)

    def test_confirm_email_twice_flashes_already_confirmed_message(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            token = registrations[0]['confirm_token']

        url = '/confirm/' + token
        self.client.get(url, follow_redirects=True)
        r = self.client.get(url, follow_redirects=True)

        msg = self.app.config['SECURITY_MSG_ALREADY_CONFIRMED'][0]
        self.assertIn(msg, r.data)

    def test_invalid_token_when_confirming_email(self):
        r = self.client.get('/confirm/bogus', follow_redirects=True)
        self.assertIn('Invalid confirmation token', r.data)

    def test_resend_confirmation(self):
        e = 'dude@lp.com'
        self.register(e)
        r = self._post('/confirm', data={'email': e})
        self.assertIn(self.get_message('CONFIRMATION_REQUEST', email=e), r.data)


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

        with self.app.extensions['mail'].record_messages() as outbox:
            r = self.client.get('/confirm/' + token, follow_redirects=True)

            self.assertEqual(len(outbox), 1)
            self.assertNotIn(token, outbox[0].html)

            expire_text = self.AUTH_CONFIG['SECURITY_CONFIRM_EMAIL_WITHIN']
            msg = self.app.config['SECURITY_MSG_CONFIRMATION_EXPIRED'][0] % dict(within=expire_text, email=e)
            self.assertIn(msg, r.data)


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
        'SECURITY_RESET_PASSWORD_ERROR_VIEW': '/',
        'SECURITY_POST_FORGOT_VIEW': '/'
    }

    def test_forgot_post_sends_email(self):
        with capture_reset_password_requests():
            with self.app.extensions['mail'].record_messages() as outbox:
                self.client.post('/reset', data=dict(email='joe@lp.com'))
                self.assertEqual(len(outbox), 1)

    def test_forgot_password_invalid_email(self):
        r = self.client.post('/reset',
                             data=dict(email='larry@lp.com'),
                             follow_redirects=True)
        self.assertIn("Specified user does not exist", r.data)

    def test_reset_password_with_valid_token(self):
        with capture_reset_password_requests() as requests:
            r = self.client.post('/reset',
                                 data=dict(email='joe@lp.com'),
                                 follow_redirects=True)
            t = requests[0]['token']

        r = self._post('/reset/' + t, data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)

        r = self.authenticate('joe@lp.com', 'newpassword')
        self.assertIn('Hello joe@lp.com', r.data)

    def test_reset_password_with_invalid_token(self):
        r = self._post('/reset/bogus', data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)

        self.assertIn(self.get_message('INVALID_RESET_PASSWORD_TOKEN'), r.data)


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


class TrackableTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_TRACKABLE': True
    }

    def test_did_track(self):
        e = 'matt@lp.com'
        self.authenticate(email=e)
        self.logout()
        self.authenticate(email=e)

        with self.app.test_request_context('/profile'):
            user = self.app.security.datastore.find_user(email=e)
            self.assertIsNotNone(user.last_login_at)
            self.assertIsNotNone(user.current_login_at)
            self.assertEquals('untrackable', user.last_login_ip)
            self.assertEquals('untrackable', user.current_login_ip)
            self.assertEquals(2, user.login_count)


class PasswordlessTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_PASSWORDLESS': True,
    }

    def test_login_request_for_inactive_user(self):
        msg = self.app.config['SECURITY_MSG_DISABLED_ACCOUNT'][0]
        r = self.client.post('/login', data=dict(email='tiya@lp.com'), follow_redirects=True)
        self.assertIn(msg, r.data)

    def test_request_login_token_sends_email_and_can_login(self):
        e = 'matt@lp.com'
        r, user, token = None, None, None

        with capture_passwordless_login_requests() as requests:
            with self.app.extensions['mail'].record_messages() as outbox:
                r = self.client.post('/login', data=dict(email=e), follow_redirects=True)

                self.assertEqual(len(outbox), 1)

                self.assertEquals(1, len(requests))
                self.assertIn('user', requests[0])
                self.assertIn('login_token', requests[0])

                user = requests[0]['user']
                token = requests[0]['login_token']

        msg = self.app.config['SECURITY_MSG_LOGIN_EMAIL_SENT'][0] % dict(email=user.email)
        self.assertIn(msg, r.data)

        r = self.client.get('/login/' + token, follow_redirects=True)
        self.assertIn(self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'), r.data)

        r = self.client.get('/profile')
        self.assertIn('Profile Page', r.data)

    def test_invalid_login_token(self):
        msg = self.app.config['SECURITY_MSG_INVALID_LOGIN_TOKEN'][0]
        r = self._get('/login/bogus', follow_redirects=True)
        self.assertIn(msg, r.data)

    def test_token_login_forwards_to_post_login_view_when_already_authenticated(self):
        with capture_passwordless_login_requests() as requests:
            self.client.post('/login', data=dict(email='matt@lp.com'), follow_redirects=True)
            token = requests[0]['login_token']

        r = self.client.get('/login/' + token, follow_redirects=True)
        self.assertIn(self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'), r.data)

        r = self.client.get('/login/' + token, follow_redirects=True)
        self.assertNotIn(self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'), r.data)


class ExpiredLoginTokenTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_PASSWORDLESS': True,
        'SECURITY_LOGIN_WITHIN': '1 seconds'
    }

    def test_expired_login_token_sends_email(self):
        e = 'matt@lp.com'

        with capture_passwordless_login_requests() as requests:
            self.client.post('/login', data=dict(email=e), follow_redirects=True)
            token = requests[0]['login_token']

        time.sleep(3)

        with self.app.extensions['mail'].record_messages() as outbox:
            r = self.client.get('/login/' + token, follow_redirects=True)

            self.assertEqual(len(outbox), 1)
            self.assertIn(e, outbox[0].html)
            self.assertNotIn(token, outbox[0].html)

            expire_text = self.AUTH_CONFIG['SECURITY_LOGIN_WITHIN']
            msg = self.app.config['SECURITY_MSG_LOGIN_EXPIRED'][0] % dict(within=expire_text, email=e)
            self.assertIn(msg, r.data)


class MongoEngineSecurityTests(DefaultSecurityTests):

    def _create_app(self, auth_config):
        from tests.test_app.mongoengine import create_app
        return create_app(auth_config)


class DefaultDatastoreTests(SecurityTest):

    def test_add_role_to_user(self):
        r = self._get('/coverage/add_role_to_user')
        self.assertIn('success', r.data)

    def test_remove_role_from_user(self):
        r = self._get('/coverage/remove_role_from_user')
        self.assertIn('success', r.data)

    def test_activate_user(self):
        r = self._get('/coverage/activate_user')
        self.assertIn('success', r.data)

    def test_deactivate_user(self):
        r = self._get('/coverage/deactivate_user')
        self.assertIn('success', r.data)

    def test_invalid_role(self):
        r = self._get('/coverage/invalid_role')
        self.assertIn('success', r.data)


class MongoEngineDatastoreTests(DefaultDatastoreTests):

    def _create_app(self, auth_config):
        from tests.test_app.mongoengine import create_app
        return create_app(auth_config)
