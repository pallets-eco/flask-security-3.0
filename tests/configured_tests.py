# -*- coding: utf-8 -*-

# from __future__ import with_statement

import base64
import time
import simplejson as json
import flask

from flask_security.utils import capture_registrations, \
    capture_reset_password_requests, capture_passwordless_login_requests
from flask_security.forms import LoginForm, ConfirmRegisterForm, RegisterForm, \
    ForgotPasswordForm, ResetPasswordForm, SendConfirmationForm, \
    PasswordlessLoginForm
from flask_security.forms import TextField, SubmitField, valid_user_email

from flask_security.signals import user_registered


from tests import SecurityTest

# TODO: Wait for passlib + bcrypt python3 compatibility to be fixed
# class ConfiguredPasswordHashSecurityTests(SecurityTest):

#     AUTH_CONFIG = {
#         'SECURITY_PASSWORD_HASH': 'bcrypt',
#         'SECURITY_PASSWORD_SALT': 'so-salty',
#         'USER_COUNT': 1
#     }

#     def test_authenticate(self):
#         r = self.authenticate(endpoint="/login")
#         self.assertIn(b'Home Page', r.data)


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
        self.assertIn(b"<h1>Login</h1>", r.data)

    def test_authenticate(self):
        r = self.authenticate(endpoint="/custom_login")
        self.assertIn(b'Post Login', r.data)

    def test_logout(self):
        self.authenticate(endpoint="/custom_login")
        r = self.logout(endpoint="/custom_logout")
        self.assertIn(b'Post Logout', r.data)

    def test_register_view(self):
        r = self._get('/register')
        self.assertIn(b'<h1>Register</h1>', r.data)

    def test_register(self):
        data = dict(email='dude@lp.com',
                    password='password',
                    password_confirm='password')

        r = self._post('/register', data=data, follow_redirects=True)
        self.assertIn(b'Post Register', r.data)

    def test_register_with_next_querystring_argument(self):
        data = dict(email='dude@lp.com',
                    password='password',
                    password_confirm='password')

        r = self._post('/register?next=/page1', data=data, follow_redirects=True)
        self.assertIn(b'Page 1', r.data)

    def test_register_json(self):
        data = '{ "email": "dude@lp.com", "password": "password"}'
        r = self._post('/register', data=data, content_type='application/json')
        data = json.loads(r.data)
        self.assertEquals(data['meta']['code'], 200)

    def test_register_existing_email(self):
        data = dict(email='matt@lp.com',
                    password='password',
                    password_confirm='password')
        r = self._post('/register', data=data, follow_redirects=True)
        msg = b'matt@lp.com is already associated with an account'
        self.assertIn(msg, r.data)

    def test_unauthorized(self):
        self.authenticate("joe@lp.com", endpoint="/custom_auth")
        r = self._get("/admin", follow_redirects=True)
        msg = b'You are not allowed to access the requested resouce'
        self.assertIn(msg, r.data)

    def test_default_http_auth_realm(self):
        r = self._get('/http', headers={
            'Authorization': 'Basic %s' % base64.b64encode(b"joe@lp.com:bogus")
        })
        self.assertIn(b'<h1>Unauthorized</h1>', r.data)
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


class DefaultTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_LOGIN_USER_TEMPLATE': 'custom_security/login_user.html',
    }

    def test_login_user_template(self):
        r = self._get('/login')

        self.assertIn(b'CUSTOM LOGIN USER', r.data)


class RegisterableTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_REGISTERABLE': True,
        'SECURITY_REGISTER_USER_TEMPLATE': 'custom_security/register_user.html'
    }

    def test_register_user_template(self):
        r = self._get('/register')

        self.assertIn(b'CUSTOM REGISTER USER', r.data)


class RecoverableTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
        'SECURITY_FORGOT_PASSWORD_TEMPLATE': 'custom_security/forgot_password.html',
        'SECURITY_RESET_PASSWORD_TEMPLATE': 'custom_security/reset_password.html',
    }

    def test_forgot_password_template(self):
        r = self._get('/reset')

        self.assertIn(b'CUSTOM FORGOT PASSWORD', r.data)

    def test_reset_password_template(self):
        with capture_reset_password_requests() as requests:
            r = self._post('/reset', data=dict(email='joe@lp.com'),
                           follow_redirects=True)

            t = requests[0]['token']

        r = self._get('/reset/' + t)

        self.assertIn(b'CUSTOM RESET PASSWORD', r.data)


class ConfirmableTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_SEND_CONFIRMATION_TEMPLATE': 'custom_security/send_confirmation.html'
    }

    def test_send_confirmation_template(self):
        r = self._get('/confirm')

        self.assertIn(b'CUSTOM SEND CONFIRMATION', r.data)


class PasswordlessTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_PASSWORDLESS': True,
        'SECURITY_SEND_LOGIN_TEMPLATE': 'custom_security/send_login.html'
    }

    def test_send_login_template(self):
        r = self._get('/login')

        self.assertIn(b'CUSTOM SEND LOGIN', r.data)


class RegisterableTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_REGISTERABLE': True,
        'USER_COUNT': 1
    }

    def test_register_valid_user(self):
        data = dict(email='dude@lp.com',
                    password='password',
                    password_confirm='password')
        self._post('/register', data=data, follow_redirects=True)
        r = self.authenticate('dude@lp.com')
        self.assertIn(b'Hello dude@lp.com', r.data)


class ConfirmableTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_REGISTERABLE': True,
        'SECURITY_EMAIL_SUBJECT_REGISTER': 'Custom welcome subject',
        'USER_COUNT': 1
    }

    def test_login_before_confirmation(self):
        e = 'dude@lp.com'
        self.register(e)
        r = self.authenticate(email=e)
        self.assertIn(self.get_message('CONFIRMATION_REQUIRED').encode('utf-8'), r.data)

    def test_send_confirmation_of_already_confirmed_account(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            r = self.register(e)
            token = registrations[0]['confirm_token']

        self.client.get('/confirm/' + token, follow_redirects=True)
        self.logout()
        r = self._post('/confirm', data=dict(email=e))
        m = self.get_message('ALREADY_CONFIRMED')
        self.assertIn(m.encode('utf-8'), r.data)

    def test_register_sends_confirmation_email(self):
        e = 'dude@lp.com'
        with self.app.extensions['mail'].record_messages() as outbox:
            self.register(e)
            self.assertEqual(len(outbox), 1)
            self.assertIn(e, outbox[0].html)
            self.assertEqual('Custom welcome subject', outbox[0].subject)

    def test_confirm_email(self):
        e = 'dude@lp.com'

        tokens = []
        def on_registered(sender, **kwargs):
            tokens.append(kwargs['confirm_token'])

        user_registered.connect(on_registered, self.app)

        r = self.register(e)
        self.assertEqual(len(tokens), 1)
        r = self.client.get('/confirm/' + tokens[0], follow_redirects=True)
        msg = self.app.config['SECURITY_MSG_EMAIL_CONFIRMED'][0]
        self.assertIn(msg.encode('utf-8'), r.data)

    def test_invalid_token_when_confirming_email(self):
        r = self.client.get('/confirm/bogus', follow_redirects=True)
        msg = self.app.config['SECURITY_MSG_INVALID_CONFIRMATION_TOKEN'][0]
        self.assertIn(msg.encode('utf-8'), r.data)

    def test_send_confirmation_json(self):
        r = self._post('/confirm', data='{"email": "matt@lp.com"}',
                       content_type='application/json')
        self.assertEquals(r.status_code, 200)

    def test_send_confirmation_with_invalid_email(self):
        r = self._post('/confirm', data=dict(email='bogus@bogus.com'))
        msg = self.app.config['SECURITY_MSG_USER_DOES_NOT_EXIST'][0]
        self.assertIn(msg.encode('utf-8'), r.data)

    def test_resend_confirmation(self):
        e = 'dude@lp.com'
        self.register(e)
        r = self._post('/confirm', data={'email': e})

        msg = self.get_message('CONFIRMATION_REQUEST', email=e).encode('utf-8')
        self.assertIn(msg, r.data)

    def test_user_deleted_before_confirmation(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            user = registrations[0]['user']
            token = registrations[0]['confirm_token']

        with self.app.app_context():
            from flask_security.core import _security
            _security.datastore.delete(user)
            _security.datastore.commit()

        r = self.client.get('/confirm/' + token, follow_redirects=True)
        msg = self.app.config['SECURITY_MSG_INVALID_CONFIRMATION_TOKEN'][0]
        self.assertIn(msg.encode('utf-8'), r.data)


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
            self.assertIn(msg.encode('utf-8'), r.data)


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
        r = self._post('/register', data=data, follow_redirects=True)
        self.assertIn(e.encode('utf-8'), r.data)

    def test_confirm_email_of_user_different_than_current_user(self):
        e1 = 'dude@lp.com'
        e2 = 'lady@lp.com'

        with capture_registrations() as registrations:
            self.register(e1)
            self.register(e2)
            token1 = registrations[0]['confirm_token']
            token2 = registrations[1]['confirm_token']

        self.client.get('/confirm/' + token1, follow_redirects=True)
        self.client.get('/logout')
        self.authenticate(email=e1)
        r = self.client.get('/confirm/' + token2, follow_redirects=True)
        m = self.app.config['SECURITY_MSG_EMAIL_CONFIRMED'][0]
        self.assertIn(m.encode('utf-8'), r.data)
        self.assertIn(b'Hello lady@lp.com', r.data)

    def test_login_unconfirmed_user_when_login_without_confirmation_is_true(self):
        e = 'dude@lp.com'
        p = 'password'
        data = dict(email=e, password=p, password_confirm=p)
        r = self._post('/register', data=data, follow_redirects=True)
        self.assertIn(e.encode('utf-8'), r.data)
        self.client.get('/logout')
        r = self.authenticate(email=e)
        self.assertIn(e.encode('utf-8'), r.data)


class RecoverableTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
        'SECURITY_RESET_PASSWORD_ERROR_VIEW': '/',
        'SECURITY_POST_FORGOT_VIEW': '/'
    }

    def test_reset_view(self):
        with capture_reset_password_requests() as requests:
            r = self._post('/reset', data=dict(email='joe@lp.com'),
                           follow_redirects=True)
            t = requests[0]['token']
        r = self._get('/reset/' + t)
        self.assertIn(b'<h1>Reset password</h1>', r.data)

    def test_forgot_post_sends_email(self):
        with capture_reset_password_requests():
            with self.app.extensions['mail'].record_messages() as outbox:
                self._post('/reset', data=dict(email='joe@lp.com'))
                self.assertEqual(len(outbox), 1)

    def test_forgot_password_json(self):
        r = self._post('/reset', data='{"email": "matt@lp.com"}',
                       content_type="application/json")
        self.assertEquals(r.status_code, 200)

    def test_forgot_password_invalid_email(self):
        r = self._post('/reset', data=dict(email='larry@lp.com'),
                       follow_redirects=True)
        self.assertIn(b"Specified user does not exist", r.data)

    def test_reset_password_with_valid_token(self):
        with capture_reset_password_requests() as requests:
            r = self._post('/reset', data=dict(email='joe@lp.com'),
                           follow_redirects=True)
            t = requests[0]['token']

        r = self._post('/reset/' + t, data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)

        r = self.logout()
        r = self.authenticate('joe@lp.com', 'newpassword')
        self.assertIn(b'Hello joe@lp.com', r.data)

    def test_reset_password_with_invalid_token(self):
        r = self._post('/reset/bogus', data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)
        m = self.get_message('INVALID_RESET_PASSWORD_TOKEN')
        self.assertIn(m.encode('utf-8'), r.data)

    def test_reset_password_with_mangled_token(self):
        t = "WyIxNjQ2MzYiLCIxMzQ1YzBlZmVhM2VhZjYwODgwMDhhZGU2YzU0MzZjMiJd.BZEw_Q.lQyo3npdPZtcJ_sNHVHP103syjM&url_id=fbb89a8328e58c181ea7d064c2987874bc54a23d"
        r = self._post('/reset/' + t, data={
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
            r = self._post('/reset', data=dict(email='joe@lp.com'),
                           follow_redirects=True)
            t = requests[0]['token']

        time.sleep(1)

        r = self._post('/reset/' + t, data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)

        self.assertIn(b'You did not reset your password within', r.data)


class ChangePasswordTest(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
        'SECURITY_CHANGEABLE': True,
    }

    def test_change_password(self):
        self.authenticate()
        r = self.client.get('/change', follow_redirects=True)
        self.assertIn(b'Change password', r.data)

    def test_change_password_invalid(self):
        self.authenticate()
        r = self._post('/change', data={
            'password': 'notpassword',
            'new_password': 'newpassword',
            'new_password_confirm': 'newpassword'
        }, follow_redirects=True)
        self.assertNotIn(b'You successfully changed your password', r.data)
        self.assertIn(b'Invalid password', r.data)

    def test_change_password_mismatch(self):
        self.authenticate()
        r = self._post('/change', data={
            'password': 'password',
            'new_password': 'newpassword',
            'new_password_confirm': 'notnewpassword'
        }, follow_redirects=True)
        self.assertNotIn(b'You successfully changed your password', r.data)
        self.assertIn(b'Passwords do not match', r.data)

    def test_change_password_bad_password(self):
        self.authenticate()
        r = self._post('/change', data={
            'password': 'password',
            'new_password': 'a',
            'new_password_confirm': 'a'
        }, follow_redirects=True)
        self.assertNotIn(b'You successfully changed your password', r.data)
        self.assertIn(b'Password must be at least 6 characters', r.data)

    def test_change_password_same_as_previous(self):
        self.authenticate()
        r = self._post('/change', data={
            'password': 'password',
            'new_password': 'password',
            'new_password_confirm': 'password'
        }, follow_redirects=True)
        self.assertNotIn(b'You successfully changed your password', r.data)
        self.assertIn(b'Your new password must be different than your previous password.', r.data)

    def test_change_password_success(self):
        data = {
            'password': 'password',
            'new_password': 'newpassword',
            'new_password_confirm': 'newpassword'
        }

        self.authenticate()
        with self.app.extensions['mail'].record_messages() as outbox:
            r = self._post('/change', data=data, follow_redirects=True)

        self.assertIn(b'You successfully changed your password', r.data)
        self.assertIn(b'Home Page', r.data)

        self.assertEqual(len(outbox), 1)
        self.assertIn("Your password has been changed", outbox[0].html)
        self.assertIn("/reset", outbox[0].html)


class EmailConfigTest(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_SEND_REGISTER_EMAIL': False,
        'SECURITY_SEND_PASSWORD_CHANGE_EMAIL': False,
    }

    def test_change_password_success_email_option(self):
        """Test the change password email can be turned off w/ configuration."""

        data = {
            'password': 'password',
            'new_password': 'newpassword',
            'new_password_confirm': 'newpassword'
        }

        self.authenticate()
        with self.app.extensions['mail'].record_messages() as outbox:
            self._post('/change', data=data, follow_redirects=True)
        self.assertEqual(len(outbox), 0)


class ChangePasswordPostViewTest(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_CHANGEABLE': True,
        'SECURITY_POST_CHANGE_VIEW': '/profile',
    }

    def test_change_password_success(self):
        data = {
            'password': 'password',
            'new_password': 'newpassword',
            'new_password_confirm': 'newpassword'
        }
        self.authenticate()
        r = self._post('/change', data=data, follow_redirects=True)

        self.assertIn(b'Profile Page', r.data)


class ChangePasswordDisabledTest(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_CHANGEABLE': False,
    }

    def test_change_password_endpoint_is_404(self):
        self.authenticate()
        r = self.client.get('/change', follow_redirects=True)
        self.assertEqual(404, r.status_code)


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
        r = self._post('/login', data=dict(email='tiya@lp.com'),
                       follow_redirects=True)
        self.assertIn(msg.encode('utf-8'), r.data)

    def test_request_login_token_with_json_and_valid_email(self):
        data = '{"email": "matt@lp.com", "password": "password"}'
        r = self._post('/login', data=data, content_type='application/json')
        self.assertEquals(r.status_code, 200)
        self.assertNotIn(b'error', r.data)

    def test_request_login_token_with_json_and_invalid_email(self):
        data = '{"email": "nobody@lp.com", "password": "password"}'
        r = self._post('/login', data=data, content_type='application/json')
        self.assertIn(b'errors', r.data)

    def test_request_login_token_sends_email_and_can_login(self):
        e = 'matt@lp.com'
        r, user, token = None, None, None

        with capture_passwordless_login_requests() as requests:
            with self.app.extensions['mail'].record_messages() as outbox:
                r = self._post('/login', data=dict(email=e),
                               follow_redirects=True)

                self.assertEqual(len(outbox), 1)

                self.assertEquals(1, len(requests))
                self.assertIn('user', requests[0])
                self.assertIn('login_token', requests[0])

                user = requests[0]['user']
                token = requests[0]['login_token']

        msg = self.app.config['SECURITY_MSG_LOGIN_EMAIL_SENT'][0]
        msg = msg % dict(email=user.email)
        self.assertIn(msg.encode('utf-8'), r.data)

        r = self.client.get('/login/' + token, follow_redirects=True)
        msg = self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL').encode('utf-8')
        self.assertIn(msg, r.data)

        r = self.client.get('/profile')
        self.assertIn(b'Profile Page', r.data)

    def test_invalid_login_token(self):
        m = self.app.config['SECURITY_MSG_INVALID_LOGIN_TOKEN'][0]
        r = self._get('/login/bogus', follow_redirects=True)
        self.assertIn(m.encode('utf-8'), r.data)

    def test_token_login_when_already_authenticated(self):
        with capture_passwordless_login_requests() as requests:
            self._post('/login', data=dict(email='matt@lp.com'),
                       follow_redirects=True)
            token = requests[0]['login_token']

        r = self.client.get('/login/' + token, follow_redirects=True)
        msg = self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL')
        self.assertIn(msg.encode('utf-8'), r.data)

        r = self.client.get('/login/' + token, follow_redirects=True)
        msg = self.get_message('PASSWORDLESS_LOGIN_SUCCESSFUL')
        self.assertNotIn(msg.encode('utf-8'), r.data)

    def test_send_login_with_invalid_email(self):
        r = self._post('/login', data=dict(email='bogus@bogus.com'))
        self.assertIn(b'Specified user does not exist', r.data)


class ExpiredLoginTokenTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_PASSWORDLESS': True,
        'SECURITY_LOGIN_WITHIN': '1 milliseconds',
        'USER_COUNT': 1
    }

    def test_expired_login_token_sends_email(self):
        e = 'matt@lp.com'

        with capture_passwordless_login_requests() as requests:
            self._post('/login', data=dict(email=e), follow_redirects=True)
            token = requests[0]['login_token']

        time.sleep(1.25)

        with self.app.extensions['mail'].record_messages() as outbox:
            r = self.client.get('/login/' + token, follow_redirects=True)

            expire_text = self.AUTH_CONFIG['SECURITY_LOGIN_WITHIN']
            msg = self.app.config['SECURITY_MSG_LOGIN_EXPIRED'][0]
            msg = msg % dict(within=expire_text, email=e)
            self.assertIn(msg.encode('utf-8'), r.data)
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

        self._post('/reset', data=dict(email='matt@lp.com'))
        self.assertTrue(self.mail_sent)


class NoBlueprintTests(SecurityTest):

    APP_KWARGS = {
        'register_blueprint': False,
    }

    AUTH_CONFIG = {
        'USER_COUNT': 1
    }

    def test_login_endpoint_is_404(self):
        r = self._get('/login')
        self.assertEqual(404, r.status_code)

    def test_http_auth_without_blueprint(self):
        auth = base64.b64encode(b"matt@lp.com:password").decode('utf-8')
        r = self._get('/http', headers={'Authorization': 'basic %s' % auth})
        self.assertIn(b'HTTP Authentication', r.data)


class ExtendFormsTest(SecurityTest):

    class MyLoginForm(LoginForm):
        email = TextField('My Login Email Address Field')

    class MyRegisterForm(RegisterForm):
        email = TextField('My Register Email Address Field')

    APP_KWARGS = {
        'login_form': MyLoginForm,
        'register_form': MyRegisterForm,
    }

    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': False,
        'SECURITY_REGISTERABLE': True,
    }

    def test_login_view(self):
        r = self._get('/login', follow_redirects=True)
        self.assertIn(b"My Login Email Address Field", r.data)

    def test_register(self):
        r = self._get('/register', follow_redirects=True)
        self.assertIn(b"My Register Email Address Field", r.data)


class RecoverableExtendFormsTest(SecurityTest):

    class MyForgotPasswordForm(ForgotPasswordForm):
        email = TextField('My Forgot Password Email Address Field',
                          validators=[valid_user_email])

    class MyResetPasswordForm(ResetPasswordForm):
        submit = SubmitField("My Reset Password Submit Field")

    APP_KWARGS = {
        'forgot_password_form': MyForgotPasswordForm,
        'reset_password_form': MyResetPasswordForm,
    }

    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
    }

    def test_forgot_password(self):
        r = self._get('/reset', follow_redirects=True)
        self.assertIn(b"My Forgot Password Email Address Field", r.data)

    def test_reset_password(self):
        with capture_reset_password_requests() as requests:
            self._post('/reset', data=dict(email='joe@lp.com'),
                       follow_redirects=True)
            token = requests[0]['token']
        r = self._get('/reset/' + token)
        self.assertIn(b"My Reset Password Submit Field", r.data)


class PasswordlessExtendFormsTest(SecurityTest):

    class MyPasswordlessLoginForm(PasswordlessLoginForm):
        email = TextField('My Passwordless Login Email Address Field')

    APP_KWARGS = {
        'passwordless_login_form': MyPasswordlessLoginForm,
    }

    AUTH_CONFIG = {
        'SECURITY_PASSWORDLESS': True,
    }

    def test_passwordless_login(self):
        r = self._get('/login', follow_redirects=True)
        self.assertIn(b"My Passwordless Login Email Address Field", r.data)


class ConfirmableExtendFormsTest(SecurityTest):

    class MyConfirmRegisterForm(ConfirmRegisterForm):
        email = TextField('My Confirm Register Email Address Field')

    class MySendConfirmationForm(SendConfirmationForm):
        email = TextField('My Send Confirmation Email Address Field')

    APP_KWARGS = {
        'confirm_register_form': MyConfirmRegisterForm,
        'send_confirmation_form': MySendConfirmationForm,
    }

    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_REGISTERABLE': True,
    }

    def test_register(self):
        r = self._get('/register', follow_redirects=True)
        self.assertIn(b"My Confirm Register Email Address Field", r.data)

    def test_send_confirmation(self):
        r = self._get('/confirm', follow_redirects=True)
        self.assertIn(b"My Send Confirmation Email Address Field", r.data)


class AdditionalUserIdentityAttributes(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_USER_IDENTITY_ATTRIBUTES': ('email', 'username')
    }

    def test_authenticate(self):
        r = self.authenticate(email='matt')
        self.assertIn(b'Hello matt@lp.com', r.data)
