# -*- coding: utf-8 -*-

from __future__ import with_statement

import base64
import time
import simplejson as json

from flask.ext.security.utils import capture_registrations, \
    capture_reset_password_requests, capture_passwordless_login_requests
from flask.ext.security.forms import LoginForm, ConfirmRegisterForm, RegisterForm, \
    ForgotPasswordForm, ResetPasswordForm, SendConfirmationForm, \
    PasswordlessLoginForm
from flask.ext.security.forms import TextField, SubmitField, valid_user_email
from flask.ext.security.core import _get_pwd_context


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

    def test_register_with_next_querystring_argument(self):
        data = dict(email='dude@lp.com',
                    password='password',
                    password_confirm='password')

        r = self._post('/register?next=/page1', data=data, follow_redirects=True)
        self.assertIn('Page 1', r.data)

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
        msg = 'matt@lp.com is already associated with an account'
        self.assertIn(msg, r.data)

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


class _RehashConfigurationTest(SecurityTest):
    AUTH_CONFIG = {
        'USER_COUNT': 1,
    }
    def setUp(self):
        super(_RehashConfigurationTest, self).setUp()
        self._get('/')      # force database creation
        print self.app.config['SECURITY_PASSWORD_REHASH']
        self.app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
        self.app.config['SECURITY_PASSWORD_REHASH'] = self.REHASH
        self.app.extensions['security'].pwd_context = _get_pwd_context(self.app)

class RehashConfigurationTestOn(_RehashConfigurationTest):
    REHASH = True

    def test_rehash_password(self):
        e = 'matt@lp.com'
        self.authenticate(email=e)

        user = self.app.extensions['security'].datastore.find_user(email=e)
        self.assertEquals(user.password[:4], '$2a$')

class RehashConfigurationTestOff(_RehashConfigurationTest):
    REHASH = False

    def test_not_rehash_password(self):
        print self.app.config['SECURITY_PASSWORD_REHASH']
        e = 'matt@lp.com'
        self.authenticate(email=e)

        print self.app.config['SECURITY_PASSWORD_REHASH']
        user = self.app.extensions['security'].datastore.find_user(email=e)
        self.assertEquals(user.password, 'password')


class DefaultTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_LOGIN_USER_TEMPLATE': 'custom_security/login_user.html',
    }

    def test_login_user_template(self):
        r = self._get('/login')

        self.assertIn('CUSTOM LOGIN USER', r.data)


class RegisterableTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_REGISTERABLE': True,
        'SECURITY_REGISTER_USER_TEMPLATE': 'custom_security/register_user.html'
    }

    def test_register_user_template(self):
        r = self._get('/register')

        self.assertIn('CUSTOM REGISTER USER', r.data)


class RecoverableTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
        'SECURITY_FORGOT_PASSWORD_TEMPLATE': 'custom_security/forgot_password.html',
        'SECURITY_RESET_PASSWORD_TEMPLATE': 'custom_security/reset_password.html',
    }

    def test_forgot_password_template(self):
        r = self._get('/reset')

        self.assertIn('CUSTOM FORGOT PASSWORD', r.data)

    def test_reset_password_template(self):
        with capture_reset_password_requests() as requests:
            r = self._post('/reset', data=dict(email='joe@lp.com'),
                           follow_redirects=True)

            t = requests[0]['token']

        r = self._get('/reset/' + t)

        self.assertIn('CUSTOM RESET PASSWORD', r.data)


class ConfirmableTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRMABLE': True,
        'SECURITY_SEND_CONFIRMATION_TEMPLATE': 'custom_security/send_confirmation.html'
    }

    def test_send_confirmation_template(self):
        r = self._get('/confirm')

        self.assertIn('CUSTOM SEND CONFIRMATION', r.data)


class PasswordlessTemplatePathTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_PASSWORDLESS': True,
        'SECURITY_SEND_LOGIN_TEMPLATE': 'custom_security/send_login.html'
    }

    def test_send_login_template(self):
        r = self._get('/login')

        self.assertIn('CUSTOM SEND LOGIN', r.data)


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
        self.assertIn('Hello dude@lp.com', r.data)


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
        self.assertIn(self.get_message('CONFIRMATION_REQUIRED'), r.data)

    def test_send_confirmation_of_already_confirmed_account(self):
        e = 'dude@lp.com'

        with capture_registrations() as registrations:
            self.register(e)
            token = registrations[0]['confirm_token']

        self.client.get('/confirm/' + token, follow_redirects=True)
        self.logout()
        r = self._post('/confirm', data=dict(email=e))
        self.assertIn(self.get_message('ALREADY_CONFIRMED'), r.data)

    def test_register_sends_confirmation_email(self):
        e = 'dude@lp.com'
        with self.app.extensions['mail'].record_messages() as outbox:
            self.register(e)
            self.assertEqual(len(outbox), 1)
            self.assertIn(e, outbox[0].html)
            self.assertEqual('Custom welcome subject', outbox[0].subject)

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
        msg = self.app.config['SECURITY_MSG_INVALID_CONFIRMATION_TOKEN'][0]
        self.assertIn(msg, r.data)

    def test_send_confirmation_json(self):
        r = self._post('/confirm', data='{"email": "matt@lp.com"}',
                       content_type='application/json')
        self.assertEquals(r.status_code, 200)

    def test_send_confirmation_with_invalid_email(self):
        r = self._post('/confirm', data=dict(email='bogus@bogus.com'))
        msg = self.app.config['SECURITY_MSG_USER_DOES_NOT_EXIST'][0]
        self.assertIn(msg, r.data)

    def test_resend_confirmation(self):
        e = 'dude@lp.com'
        self.register(e)
        r = self._post('/confirm', data={'email': e})

        msg = self.get_message('CONFIRMATION_REQUEST', email=e)
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
        r = self._post('/register', data=data, follow_redirects=True)
        self.assertIn(e, r.data)

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
        msg = self.app.config['SECURITY_MSG_EMAIL_CONFIRMED'][0]
        self.assertIn(msg, r.data)
        self.assertIn('Hello %s' % e2, r.data)


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
        self.assertIn('<h1>Reset password</h1>', r.data)

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
        self.assertIn("Specified user does not exist", r.data)

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
            r = self._post('/reset', data=dict(email='joe@lp.com'),
                           follow_redirects=True)
            t = requests[0]['token']

        time.sleep(1)

        r = self._post('/reset/' + t, data={
            'password': 'newpassword',
            'password_confirm': 'newpassword'
        }, follow_redirects=True)

        self.assertIn('You did not reset your password within', r.data)


class ChangePasswordTest(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_RECOVERABLE': True,
        'SECURITY_CHANGEABLE': True,
    }

    def test_change_password(self):
        self.authenticate()
        r = self.client.get('/change', follow_redirects=True)
        self.assertIn('Change password', r.data)

    def test_change_password_invalid(self):
        self.authenticate()
        r = self._post('/change', data={
            'password': 'notpassword',
            'new_password': 'newpassword',
            'new_password_confirm': 'newpassword'
        }, follow_redirects=True)
        self.assertNotIn('You successfully changed your password', r.data)
        self.assertIn('Invalid password', r.data)

    def test_change_password_mismatch(self):
        self.authenticate()
        r = self._post('/change', data={
            'password': 'password',
            'new_password': 'newpassword',
            'new_password_confirm': 'notnewpassword'
        }, follow_redirects=True)
        self.assertNotIn('You successfully changed your password', r.data)
        self.assertIn('Passwords do not match', r.data)

    def test_change_password_bad_password(self):
        self.authenticate()
        r = self._post('/change', data={
            'password': 'password',
            'new_password': 'a',
            'new_password_confirm': 'a'
        }, follow_redirects=True)
        self.assertNotIn('You successfully changed your password', r.data)
        self.assertIn('Password must be at least 6 characters', r.data)

    def test_change_password_success(self):
        data = {
            'password': 'password',
            'new_password': 'newpassword',
            'new_password_confirm': 'newpassword'
        }

        self.authenticate()
        with self.app.extensions['mail'].record_messages() as outbox:
            r = self._post('/change', data=data, follow_redirects=True)

        self.assertIn('You successfully changed your password', r.data)
        self.assertIn('Home Page', r.data)

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
            r = self._post('/change', data=data, follow_redirects=True)

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

        self.assertIn('Profile Page', r.data)


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
        self.assertIn(msg, r.data)

    def test_request_login_token_with_json_and_valid_email(self):
        data = '{"email": "matt@lp.com", "password": "password"}'
        r = self._post('/login', data=data, content_type='application/json')
        self.assertEquals(r.status_code, 200)
        self.assertNotIn('error', r.data)

    def test_request_login_token_with_json_and_invalid_email(self):
        data = '{"email": "nobody@lp.com", "password": "password"}'
        r = self._post('/login', data=data, content_type='application/json')
        self.assertIn('errors', r.data)

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
            self._post('/login', data=dict(email='matt@lp.com'),
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
            self._post('/login', data=dict(email=e), follow_redirects=True)
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
        auth = 'Basic ' + base64.b64encode("matt@lp.com:password")
        r = self._get('/http', headers={'Authorization': auth})
        self.assertIn('HTTP Authentication', r.data)


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
        self.assertIn("My Login Email Address Field", r.data)

    def test_register(self):
        r = self._get('/register', follow_redirects=True)
        self.assertIn("My Register Email Address Field", r.data)


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
        self.assertIn("My Forgot Password Email Address Field", r.data)

    def test_reset_password(self):
        with capture_reset_password_requests() as requests:
            self._post('/reset', data=dict(email='joe@lp.com'),
                       follow_redirects=True)
            token = requests[0]['token']
        r = self._get('/reset/' + token)
        self.assertIn("My Reset Password Submit Field", r.data)


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
        self.assertIn("My Passwordless Login Email Address Field", r.data)


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
        self.assertIn("My Confirm Register Email Address Field", r.data)

    def test_send_confirmation(self):
        r = self._get('/confirm', follow_redirects=True)
        self.assertIn("My Send Confirmation Email Address Field", r.data)
