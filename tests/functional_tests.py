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
                content_type=content_type or 'text/html')
        
    
    def authenticate(self, username, password, endpoint=None):
        data = dict(username=username, password=password)
        return self._post(endpoint or '/auth', data=data, 
                content_type='application/x-www-form-urlencoded')
    
    def logout(self, endpoint=None):
        return self._get(endpoint or '/logout', follow_redirects=True)

class DefaultSecurityTests(SecurityTest):
    
    def test_login_view(self):
        r = self._get('/login')
        assert 'Login Page' in r.data
        
    def test_authenticate(self):
        r = self.authenticate("matt", "password")
        assert 'Home Page' in r.data
        
    def test_unprovided_username(self):
        r = self.authenticate("", "password")
        assert "Username not provided" in r.data
        
    def test_unprovided_password(self):
        r = self.authenticate("matt", "")
        assert "Password not provided" in r.data
    
    def test_invalid_user(self):
        r = self.authenticate("bogus", "password")
        assert "Specified user does not exist" in r.data
        
    def test_bad_password(self):
        r = self.authenticate("matt", "bogus")
        assert "Password does not match" in r.data
        
    def test_inactive_user(self):
        r = self.authenticate("tiya", "password")
        assert "Inactive user" in r.data
        
    def test_logout(self):
        self.authenticate("matt", "password")
        r = self.logout()
        assert 'Home Page' in r.data
        
    def test_unauthorized_access(self):
        r = self._get('/profile', follow_redirects=True)
        assert 'Please log in to access this page' in r.data
        
    def test_authorized_access(self):
        self.authenticate("matt", "password")
        r = self._get("/profile")
        assert 'profile' in r.data
        
    def test_valid_admin_role(self):
        self.authenticate("matt", "password")
        r = self._get("/admin")
        assert 'Admin Page' in r.data
        
    def test_invalid_admin_role(self):
        self.authenticate("joe", "password")
        r = self._get("/admin", follow_redirects=True)
        assert 'Home Page' in r.data
        
    def test_roles_accepted(self):
        for user in ("matt", "joe"):
            self.authenticate(user, "password")
            r = self._get("/admin_or_editor")
            self.assertIn('Admin or Editor Page', r.data)
            self.logout()
            
        self.authenticate("jill", "password")
        r = self._get("/admin_or_editor", follow_redirects=True)
        self.assertIn('Home Page', r.data)


class ConfiguredSecurityTests(SecurityTest):    
    
    AUTH_CONFIG = {
        'password_hash': 'bcrypt',
        'user_datastore_name': 'custom_datastore_name',
        'auth_url': '/custom_auth',
        'logout_url': '/custom_logout',
        'login_view': '/custom_login',
        'post_login_view': '/post_login',
        'post_logout_view': '/post_logout'
    }
    
    def test_login_view(self):
        r = self._get('/custom_login')
        assert "Custom Login Page" in r.data
    
    def test_authenticate(self):
        r = self.authenticate("matt", "password", endpoint="/custom_auth")
        assert 'Post Login' in r.data
        
    def test_logout(self):
        self.authenticate("matt", "password", endpoint="/custom_auth")
        r = self.logout(endpoint="/custom_logout")
        assert 'Post Logout' in r.data

        
class MongoEngineSecurityTests(DefaultSecurityTests):
    
    def _create_app(self, auth_config):
        return app.create_mongoengine_app(auth_config)        
