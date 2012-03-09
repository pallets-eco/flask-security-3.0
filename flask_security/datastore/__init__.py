from datetime import datetime
from flask.ext import security
from flask.ext.security import UserCreationError, RoleCreationError, pwd_context

class UserDatastore(object):
    """Abstracted user datastore. Always extend this and implement
    missing methods"""
    
    def _do_with_id(self, id):
        raise NotImplementedError(
            "User datastore does not implement _do_with_id method")
    
    def _do_find_user(self):
        raise NotImplementedError(
            "User datastore does not implement _do_find_user method")
    
    def _do_find_role(self):
        raise NotImplementedError(
            "User datastore does not implement _do_find_role method")
        
    def _do_add_role(self, user, role):
        user, role = self._prepare_role_modify_args(user, role)
        if role not in user.roles:
            user.roles.append(role)
        return user
        
    def _do_remove_role(self, user, role):
        user, role = self._prepare_role_modify_args(user, role)
        if role in user.roles:
            user.roles.remove(role)
        return user
    
    def _prepare_role_modify_args(self, user, role):
        if isinstance(user, security.User):
            user = user.username or user.email
        
        if isinstance(role, security.Role):
            role = role.name
            
        return self.find_user(user), self.find_role(role)
        
    def _prepare_create_role_args(self, kwargs):
        for key in ('name', 'description'):
            kwargs[key] = kwargs.get(key, None)
        
        if kwargs['name'] is None:
            raise RoleCreationError("Missing name argument")
        
        return kwargs
    
    def _prepare_create_user_args(self, kwargs):
        username = kwargs.get('username', None)
        email = kwargs.get('email', None)
        password = kwargs.get('password', None)
        
        if username is None and email is None:
            raise UserCreationError('Missing username and/or email arguments')
            
        if password is None:
            raise UserCreationError('Missing password argument')
            
        roles = kwargs.get('roles', [])
        
        for i, role in enumerate(roles):
            rn = role.name if isinstance(role, security.Role) else role
            # see if the role exists
            roles[i] = self.find_role(rn)
        
        kwargs['roles'] = roles
        
        now = datetime.utcnow()
        kwargs['created_at'], kwargs['modified_at'] = now, now
        
        pw = kwargs['password']
        if not pwd_context.identify(pw):
            kwargs['password'] = pwd_context.encrypt(pw)
            
        return kwargs
    
    def with_id(self, id):
        user = self._do_with_id(id)
        if user: return user
        raise security.UserIdNotFoundError()
    
    def find_user(self, user):
        user = self._do_find_user(user)
        if user: return user
        raise security.UserNotFoundError()
    
    def find_role(self, role):
        role = self._do_find_role(role)
        if role: return role
        raise security.RoleNotFoundError()
    
    def create_role(self, **kwargs):
        raise NotImplementedError(
            "User datastore does not implement create_role method")
        
    def create_user(self, **kwargs):
        raise NotImplementedError(
            "User datastore does not implement create_user method")
        
    def add_role_to_user(self, user, role):
        raise NotImplementedError(
            "User datastore does not implement add_role_to_user method")
        
    def remove_role_from_user(self, user, role):
        raise NotImplementedError(
            "User datastore does not implement remove_role_from_user method")