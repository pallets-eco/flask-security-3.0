# -*- coding: utf-8 -*-

from __future__ import with_statement

import base64
import simplejson as json
from cookielib import Cookie

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

    def test_invalid_user(self):
        r = self.authenticate(email="bogus@bogus.com")
        self.assertIn("Specified user does not exist", r.data)

    def test_bad_password(self):
        r = self.authenticate(password="bogus")
        self.assertIn("Invalid password", r.data)

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
        data = json.loads(r.data)
        self.assertEquals(data['meta']['code'], 200)
        self.assertIn('authentication_token', data['response']['user'])

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
        self.assertEquals('Basic realm="Login Required"',
                          r.headers['WWW-Authenticate'])

    def test_invalid_http_auth_bad_password(self):
        r = self._get('/http', headers={
            'Authorization': 'Basic ' + base64.b64encode("joe@lp.com:bogus")
        })
        self.assertIn('<h1>Unauthorized</h1>', r.data)
        self.assertIn('WWW-Authenticate', r.headers)
        self.assertEquals('Basic realm="Login Required"',
                          r.headers['WWW-Authenticate'])

    def test_custom_http_auth_realm(self):
        r = self._get('/http_custom_realm', headers={
            'Authorization': 'Basic ' + base64.b64encode("joe@lp.com:bogus")
        })
        self.assertIn('<h1>Unauthorized</h1>', r.data)
        self.assertIn('WWW-Authenticate', r.headers)
        self.assertEquals('Basic realm="My Realm"',
                          r.headers['WWW-Authenticate'])

    def test_user_deleted_during_session_reverts_to_anonymous_user(self):
        self.authenticate()

        with self.app.test_request_context('/'):
            user = self.app.security.datastore.find_user(email='matt@lp.com')
            self.app.security.datastore.delete_user(user)
            self.app.security.datastore.commit()

        r = self._get('/')
        self.assertNotIn('Hello matt@lp.com', r.data)

    def test_remember_token(self):
        r = self.authenticate(follow_redirects=False)
        self.client.cookie_jar.clear_session_cookies()
        r = self._get('/profile')
        self.assertIn('profile', r.data)

    def test_token_loader_does_not_fail_with_invalid_token(self):
        c = Cookie(version=0, name='remember_token', value='None', port=None,
                   port_specified=False, domain='www.example.com',
                   domain_specified=False, domain_initial_dot=False, path='/',
                   path_specified=True, secure=False, expires=None,
                   discard=True, comment=None, comment_url=None,
                   rest={'HttpOnly': None}, rfc2109=False)

        self.client.cookie_jar.set_cookie(c)
        r = self._get('/')
        self.assertNotIn('BadSignature', r.data)


class MongoEngineSecurityTests(DefaultSecurityTests):

    def _create_app(self, auth_config, **kwargs):
        from tests.test_app.mongoengine import create_app
        return create_app(auth_config, **kwargs)


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

    def _create_app(self, auth_config, **kwargs):
        from tests.test_app.mongoengine import create_app
        return create_app(auth_config, **kwargs)
