# -*- coding: utf-8 -*-

import unittest

from example import app


class SecurityTest(unittest.TestCase):

    AUTH_CONFIG = None

    def setUp(self):
        super(SecurityTest, self).setUp()

        self.app = self._create_app(self.AUTH_CONFIG or None)
        self.app.debug = False
        self.app.config['TESTING'] = True

        self.client = self.app.test_client()

    def _create_app(self, auth_config):
        return app.create_sqlalchemy_app(auth_config)

    def _get(self, route, content_type=None, follow_redirects=None):
        return self.client.get(route, follow_redirects=follow_redirects,
                content_type=content_type or 'text/html')

    def _post(self, route, data=None, content_type=None, follow_redirects=True):
        return self.client.post(route, data=data,
                follow_redirects=follow_redirects,
                content_type=content_type or 'application/x-www-form-urlencoded')

    def register(self, email, password, endpoint=None):
        return self._post(endpoint or '/register')

    def authenticate(self, email, password, endpoint=None):
        data = dict(email=email, password=password)
        return self._post(endpoint or '/auth', data=data)

    def logout(self, endpoint=None):
        return self._get(endpoint or '/logout', follow_redirects=True)


class DefaultSecurityTests(SecurityTest):

    def test_login_view(self):
        r = self._get('/login')
        self.assertIn('Login Page', r.data)

    def test_authenticate(self):
        r = self.authenticate("matt@lp.com", "password")
        self.assertIn('Hello matt@lp.com', r.data)

    def test_unprovided_username(self):
        r = self.authenticate("", "password")
        self.assertIn("Email not provided", r.data)

    def test_unprovided_password(self):
        r = self.authenticate("matt@lp.com", "")
        self.assertIn("Password not provided", r.data)

    def test_invalid_user(self):
        r = self.authenticate("bogus", "password")
        self.assertIn("Specified user does not exist", r.data)

    def test_bad_password(self):
        r = self.authenticate("matt@lp.com", "bogus")
        self.assertIn("Password does not match", r.data)

    def test_inactive_user(self):
        r = self.authenticate("tiya@lp.com", "password")
        self.assertIn("Inactive user", r.data)

    def test_logout(self):
        self.authenticate("matt@lp.com", "password")
        r = self.logout()
        self.assertIn('Home Page', r.data)

    def test_unauthorized_access(self):
        r = self._get('/profile', follow_redirects=True)
        self.assertIn('Please log in to access this page', r.data)

    def test_authorized_access(self):
        self.authenticate("matt@lp.com", "password")
        r = self._get("/profile")
        self.assertIn('profile', r.data)

    def test_valid_admin_role(self):
        self.authenticate("matt@lp.com", "password")
        r = self._get("/admin")
        self.assertIn('Admin Page', r.data)

    def test_invalid_admin_role(self):
        self.authenticate("joe@lp.com", "password")
        r = self._get("/admin", follow_redirects=True)
        self.assertIn('Home Page', r.data)

    def test_roles_accepted(self):
        for user in ("matt@lp.com", "joe@lp.com"):
            self.authenticate(user, "password")
            r = self._get("/admin_or_editor")
            self.assertIn('Admin or Editor Page', r.data)
            self.logout()

        self.authenticate("jill@lp.com", "password")
        r = self._get("/admin_or_editor", follow_redirects=True)
        self.assertIn('Home Page', r.data)

    def test_unauthenticated_role_required(self):
        r = self._get('/admin', follow_redirects=True)
        self.assertIn('<input id="next"', r.data)

    def test_register_valid_user(self):
        data = dict(email='dude@lp.com', password='password', password_confirm='password')
        self.client.post('/register', data=data, follow_redirects=True)
        r = self.authenticate('dude@lp.com', 'password')
        self.assertIn('Hello dude@lp.com', r.data)


class ConfiguredURLTests(SecurityTest):

    AUTH_CONFIG = {
        'SECURITY_AUTH_URL': '/custom_auth',
        'SECURITY_LOGOUT_URL': '/custom_logout',
        'SECURITY_LOGIN_VIEW': '/custom_login',
        'SECURITY_POST_LOGIN_VIEW': '/post_login',
        'SECURITY_POST_LOGOUT_VIEW': '/post_logout',
        'SECURITY_POST_REGISTER_VIEW': '/post_register'
    }

    def test_login_view(self):
        r = self._get('/custom_login')
        self.assertIn("Custom Login Page", r.data)

    def test_authenticate(self):
        r = self.authenticate("matt@lp.com", "password", endpoint="/custom_auth")
        self.assertIn('Post Login', r.data)

    def test_logout(self):
        self.authenticate("matt@lp.com", "password", endpoint="/custom_auth")
        r = self.logout(endpoint="/custom_logout")
        self.assertIn('Post Logout', r.data)

    def test_register(self):
        data = dict(email='dude@lp.com', password='password', password_confirm='password')
        r = self.client.post('/register', data=data, follow_redirects=True)
        self.assertIn('Hello dude@lp.com', r.data)
        self.assertIn('Post Register', r.data)


class ConfirmationTests(SecurityTest):
    AUTH_CONFIG = {
        'SECURITY_CONFIRM_EMAIL': True,
        'SECURITY_LOGIN_WITHOUT_CONFIRMATION': True
    }

    def test_register_valid_user_automatically_signs_in(self):
        e = 'dude@lp.com'
        p = 'password'
        data = dict(email=e, password=p, password_confirm=p)
        r = self.client.post('/register', data=data, follow_redirects=True)
        self.assertIn(e, r.data)

    def test_register_valid_user_sends_confirmation_email(self):
        e = 'dude@lp.com'
        p = 'password'
        data = dict(email=e, password=p, password_confirm=p)

        with self.app.mail.record_messages() as outbox:
            self.client.post('/register', data=data, follow_redirects=True)
            self.assertEqual(len(outbox), 1)
            self.assertIn(e, outbox[0].html)


class MongoEngineSecurityTests(DefaultSecurityTests):

    def _create_app(self, auth_config):
        return app.create_mongoengine_app(auth_config)
