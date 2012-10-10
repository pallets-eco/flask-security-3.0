from __future__ import with_statement

import base64
import time
import simplejson as json

from flask.ext.security.utils import capture_registrations, \
     capture_reset_password_requests, capture_passwordless_login_requests

from tests import SecurityTest


class ConfiguredPasswordHashSecurityTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'SECURITY_PASSWORD_SALT': 'so-salty',
        'USER_COUNT': 1
    }

    def test_authenticate(self):
        r = self.authenticate(endpoint="/login")
        self.assertIn('Home Page', r.data)


class ConfiguredSecurityTests(SecurityTest):

    AUTH_CONFIG = {
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

    def test_register_json(self):
        r = self._post('/register',
                       data='{ "email": "dude@lp.com", "password": "password" }',
                       content_type='application/json')
        data = json.loads(r.data)
        self.assertEquals(data['meta']['code'], 200)
        self.assertIn('authentication_token', data['response']['user'])

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
        self.assertEquals('Basic realm="Custom Realm"',
                          r.headers['WWW-Authenticate'])


class BadConfiguredSecurityTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_PASSWORD_HASH': 'bcrypt',
        'USER_COUNT': 1
    }

    def test_bad_configuration_raises_runtimer_error(self):
        self.assertRaises(RuntimeError, self.authenticate)


class RegisterableTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_REGISTERABLE': True,
        'USER_COUNT': 1
    }

    def test_register_valid_user(self):
        data = dict(email='dude@lp.com',
                    password='password',
                    password_confirm='password')
        self.client.post('/register', data=data, follow_redirects=True)
        r = self.authenticate('dude@lp.com')
        self.assertIn('Hello dude@lp.com', r.data)


class ConfirmableTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_REGISTERABLE': True,
        'USER_COUNT': 1
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

    def test_invalid_token_when_confirming_email(self):
        r = self.client.get('/confirm/bogus', follow_redirects=True)
        self.assertIn('Invalid confirmation token', r.data)

    def test_send_confirmation_with_invalid_email(self):
        r = self._post('/confirm', data=dict(email='bogus@bogus.com'))
        self.assertIn('Specified user does not exist', r.data)

    def test_resend_confirmation(self):
        e = 'dude@lp.com'
        self.register(e)
        r = self._post('/confirm', data={'email': e})

        msg = self.get_message('CONFIRMATION_REQUEST', email=e)
        self.assertIn(msg, r.data)


class ExpiredConfirmationTest(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_REGISTERABLE': True,
        'SECURITY_CONFIRM_EMAIL_WITHIN': '1 milliseconds',
        'USER_COUNT': 1
    }

    def test_expired_confirmation_token_sends_email(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            token = registrations[0]['confirm_token']

        time.sleep(1.25)

        with self.app.extensions['mail'].record_messages() as outbox:
            r = self.client.get('/confirm/' + token, follow_redirects=True)

            self.assertEqual(len(outbox), 1)
            self.assertNotIn(token, outbox[0].html)

            expire_text = self.AUTH_CONFIG['SECURITY_CONFIRM_EMAIL_WITHIN']
            msg = self.app.config['SECURITY_MSG_CONFIRMATION_EXPIRED'][0]
            msg = msg % dict(within=expire_text, email=e)
            self.assertIn(msg, r.data)


class LoginWithoutImmediateConfirmTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_REGISTERABLE': True,
        'SECURITY_LOGIN_WITHOUT_CONFIRMATION': True,
        'USER_COUNT': 1
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

    def test_reset_view(self):
        with capture_reset_password_requests() as requests:
            r = self.client.post('/reset',
                                 data=dict(email='joe@lp.com'),
                                 follow_redirects=True)
            t = requests[0]['token']
        r = self._get('/reset/' + t)
        self.assertIn('<h1>Reset password</h1>', r.data)

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

        r = self.logout()
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
        'SECURITY_RESET_PASSWORD_WITHIN': '1 milliseconds'
    }

    def test_reset_password_with_expired_token(self):
        with capture_reset_password_requests() as requests:
            r = self.client.post('/reset',
                                 data=dict(email='joe@lp.com'),
                                 follow_redirects=True)
            t = requests[0]['token']

        time.sleep(1)

        r = self.client.post('/reset/' + t, data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)

        self.assertIn('You did not reset your password within', r.data)


class TrackableTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_TRACKABLE': True,
        'USER_COUNT': 1
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
        'SECURITY_PASSWORDLESS': True
    }

    def test_login_request_for_inactive_user(self):
        msg = self.app.config['SECURITY_MSG_DISABLED_ACCOUNT'][0]
        r = self.client.post('/login',
                             data=dict(email='tiya@lp.com'),
                             follow_redirects=True)
        self.assertIn(msg, r.data)

    def test_request_login_token_sends_email_and_can_login(self):
        e = 'matt@lp.com'
        r, user, token = None, None, None

        with capture_passwordless_login_requests() as requests:
            with self.app.extensions['mail'].record_messages() as outbox:
                r = self.client.post('/login',
                                     data=dict(email=e),
                                     follow_redirects=True)

                self.assertEqual(len(outbox), 1)

                self.assertEquals(1, len(requests))
                self.assertIn('user', requests[0])
                self.assertIn('login_token', requests[0])

                user = requests[0]['user']
                token = requests[0]['login_token']

        msg = self.app.config['SECURITY_MSG_LOGIN_EMAIL_SENT'][0]
        msg = msg % dict(email=user.email)
        self.assertIn(msg, r.data)

        r = self.client.get('/login/' + token, follow_redirects=True)
        msg = self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL')
        self.assertIn(msg, r.data)

        r = self.client.get('/profile')
        self.assertIn('Profile Page', r.data)

    def test_invalid_login_token(self):
        msg = self.app.config['SECURITY_MSG_INVALID_LOGIN_TOKEN'][0]
        r = self._get('/login/bogus', follow_redirects=True)
        self.assertIn(msg, r.data)

    def test_token_login_when_already_authenticated(self):
        with capture_passwordless_login_requests() as requests:
            self.client.post('/login',
                             data=dict(email='matt@lp.com'),
                             follow_redirects=True)
            token = requests[0]['login_token']

        r = self.client.get('/login/' + token, follow_redirects=True)
        msg = self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL')
        self.assertIn(msg, r.data)

        r = self.client.get('/login/' + token, follow_redirects=True)
        msg = self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL')
        self.assertNotIn(msg, r.data)

    def test_send_login_with_invalid_email(self):
        r = self._post('/login', data=dict(email='bogus@bogus.com'))
        self.assertIn('Specified user does not exist', r.data)


class ExpiredLoginTokenTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_PASSWORDLESS': True,
        'SECURITY_LOGIN_WITHIN': '1 milliseconds',
        'USER_COUNT': 1
    }

    def test_expired_login_token_sends_email(self):
        e = 'matt@lp.com'

        with capture_passwordless_login_requests() as requests:
            self.client.post('/login',
                             data=dict(email=e),
                             follow_redirects=True)
            token = requests[0]['login_token']

        time.sleep(1.25)

        with self.app.extensions['mail'].record_messages() as outbox:
            r = self.client.get('/login/' + token, follow_redirects=True)

            expire_text = self.AUTH_CONFIG['SECURITY_LOGIN_WITHIN']
            msg = self.app.config['SECURITY_MSG_LOGIN_EXPIRED'][0]
            msg = msg % dict(within=expire_text, email=e)
            self.assertIn(msg, r.data)

            self.assertEqual(len(outbox), 1)
            self.assertIn(e, outbox[0].html)
            self.assertNotIn(token, outbox[0].html)


class AsyncMailTaskTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
        'USER_COUNT': 1
    }

    def setUp(self):
        super(AsyncMailTaskTests, self).setUp()
        self.mail_sent = False

    def test_send_email_task_is_called(self):
        @self.app.security.send_mail_task
        def send_email(msg):
            self.mail_sent = True

        self.client.post('/reset', data=dict(email='matt@lp.com'))
        self.assertTrue(self.mail_sent)


class NoBlueprintTests(SecurityTest):

    AUTH_CONFIG = {
        'USER_COUNT': 1
    }

    def _create_app(self, auth_config):
        return super(NoBlueprintTests, self)._create_app(auth_config, False)

    def test_login_endpoint_is_404(self):
        r = self._get('/login')
        self.assertEqual(404, r.status_code)

    def test_http_auth_without_blueprint(self):
        auth = 'Basic ' + base64.b64encode("matt@lp.com:password")
        r = self._get('/http', headers={'Authorization': auth})
        self.assertIn('HTTP Authentication', r.data)
