from types import StringType
from flask.ext import security
from flask.ext.login import UserMixin
from flask.ext.security.datastore import UserDatastore
    
class SQLAlchemyUserDatastore(UserDatastore):
    """SQLAlchemy datastore"""
    
    def __init__(self, db):
        self.db = db
        
        roles_users = db.Table('roles_users',
            db.Column('user_id', db.Integer(), db.ForeignKey('role.id')),
            db.Column('role_id', db.Integer(), db.ForeignKey('user.id')))
        
        class Role(db.Model):
            id = db.Column(db.Integer(), primary_key=True)
            name = db.Column(db.String(80), unique=True)
            description = db.Column(db.String(255))
            
            def __init__(self, name=None, description=None):
                self.name = name
                self.description = description
            
            def __eq__(self, other):
                return self.name == other.name
            
            def __ne__(self, other):
                return self.name != other.name
                
            def __str__(self):
                return '<Role name=%s, description=%s>' % (self.name, self.description)
              
        class User(db.Model, UserMixin):
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(255), unique=True)
            email = db.Column(db.String(255), unique=True)
            password = db.Column(db.String(120))
            active = db.Column(db.Boolean())
            created_at = db.Column(db.DateTime())
            modified_at = db.Column(db.DateTime())
            
            roles= db.relationship('Role', secondary=roles_users,
                                    backref=db.backref('users', lazy='dynamic'))
            
            def __init__(self, username=None, email=None, password=None, 
                         active=True, roles=None, 
                         created_at=None, modified_at=None):
                self.username = username
                self.email = email
                self.password = password
                self.active = active
                self.roles = roles or []
                self.created_at = created_at
                self.modified_at = modified_at
                
            def is_active(self):
                return self.active
            
            def has_role(self, role):
                if type(role) is StringType:
                    role = security.Role(name=role)
                return role in self.roles
            
            def __str__(self):
                return '<User id=%(id)s, email=%(email)s>' % self.__dict__
            
        security.User = User
        security.Role = Role
        
        db.create_all()
        
    def with_id(self, id):
        user = security.User.query.get(id)
        if user: return user
        raise security.UserIdNotFoundError()
    
    def find(self, user_identifier):
        user = security.User.query.filter_by(username=user_identifier).first()
        if user: return user
        user = security.User.query.filter_by(email=user_identifier).first()
        if user: return user
        raise security.UserNotFoundError()
    
    def create_role(self, commit=True, **kwargs):
        if not kwargs.has_key('name'):
            raise TypeError("create_role() did not receive "
                            "keyword argument 'name'")
        
        name = kwargs.get('name')
        description = kwargs.get('description', None)
        
        role = security.Role.query.filter_by(name=name).first()
        
        if role is None:
            role = security.Role(name=name, description=description)
            self.db.session.add(role)
            if commit: self.db.session.commit()
            
        return role 
    
    def create_user(self, commit=True, **kwargs):
        kwargs = self._prepare_create_args(kwargs)
        
        roles = kwargs.get('roles', [])
        user_roles = []
        for role in roles:
            user_roles.append(self.create_role(name=role, commit=False))
        
        kwargs['roles'] = user_roles
        user = security.User(**kwargs)
        self.db.session.add(user)
        
        if commit: self.db.session.commit()
        return user