from flask.ext import security
from flask.ext.security import UserMixin, RoleMixin
from flask.ext.security.datastore import UserDatastore
    
class MongoEngineUserDatastore(UserDatastore):
    """MongoEngine datastore"""
    
    def __init__(self, db):
        self.db = db
        
        class Role(db.Document, RoleMixin):
            name = db.StringField(required=True, unique=True, max_length=80)
            description = db.StringField(max_length=255)
              
        class User(db.Document, UserMixin):
            username = db.StringField(unique=True, max_length=255)
            email = db.StringField(unique=True, max_length=255)
            password = db.StringField(required=True, max_length=120)
            active = db.BooleanField(default=True)
            roles= db.ListField(db.ReferenceField(Role), default=[])
            created_at = db.DateTimeField()
            modified_at = db.DateTimeField()
            
        security.User = User
        security.Role = Role
        
    def with_id(self, id):
        try: return security.User.objects.get(id=id)
        except: raise security.UserIdNotFoundError()
    
    def find(self, user_identifier):
        user = security.User.objects(username=user_identifier).first()
        if user: return user
        user = security.User.objects(email=user_identifier).first()
        if user: return user
        raise security.UserNotFoundError()
    
    def create_role(self, **kwargs):
        if not kwargs.has_key('name'):
            raise TypeError("create_role() did not receive "
                            "keyword argument 'name'")
        
        name = kwargs.get('name')
        description = kwargs.get('description', None)
        
        role = security.Role.objects(name=name).first()
        
        if role is None:
            role = security.Role(name=name, description=description)
            role.save()
            
        return role
    
    def create_user(self, **kwargs):
        kwargs = self._prepare_create_args(kwargs)
        
        roles = kwargs.get('roles', [])
        user_roles = []
        for role in roles:
            user_roles.append(self.create_role(name=role))
        
        kwargs['roles'] = user_roles
        
        user = security.User(**kwargs)
        user.save()
        
        return user