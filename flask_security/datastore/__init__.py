from datetime import datetime
from flask.ext.security import UserCreationError, pwd_context

class UserDatastore(object):
    """A sort of abstract user service"""
    def with_id(self, id):
        raise NotImplementedError(
            "User datastore does not implement with_id method")
    
    def find(self, user_identifier):
        raise NotImplementedError(
            "User datastore does not implement find_user method")
    
    def create_role(self, **kwargs):
        raise NotImplementedError(
            "User datastore does not implement create_role method")
        
    def create_user(self, **kwargs):
        raise NotImplementedError(
            "User datastore does not implement create_user method")
        
    def _prepare_create_args(self, kwargs):
        if not kwargs.has_key('username') and not kwargs.has_key('email'):
            raise UserCreationError('Error creating user: username and/or '
                                    'email arguments not provided')
            
        if not kwargs.has_key('password'):
            raise UserCreationError('Error creating user: password '
                                    'argument not provided')
            
        now = datetime.utcnow()
        kwargs['created_at'], kwargs['modified_at'] = now, now
        
        pw = kwargs['password']
        if not pwd_context.identify(pw):
            kwargs['password'] = pwd_context.encrypt(pw)
            
        return kwargs