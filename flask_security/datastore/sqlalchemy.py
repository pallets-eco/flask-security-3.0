from flask.ext import security
from flask.ext.security import UserMixin, RoleMixin
from flask.ext.security.datastore import UserDatastore
    
class SQLAlchemyUserDatastore(UserDatastore):
    """SQLAlchemy datastore"""
    
    def __init__(self, db):
        self.db = db
        
    def get_models(self):
        db = self.db
        
        roles_users = db.Table('roles_users',
            db.Column('user_id', db.Integer(), db.ForeignKey('role.id')),
            db.Column('role_id', db.Integer(), db.ForeignKey('user.id')))
        
        class Role(db.Model, RoleMixin):
            id = db.Column(db.Integer(), primary_key=True)
            name = db.Column(db.String(80), unique=True)
            description = db.Column(db.String(255))
            
            def __init__(self, name=None, description=None):
                self.name = name
                self.description = description
              
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
            
        return User, Role
    
    def _save_model(self, model):
        self.db.session.add(model)
        self.db.session.commit()
        return model
    
    def _do_with_id(self, id):
        return security.User.query.get(id)
    
    def _do_find_user(self, user):
        return security.User.query.filter_by(username=user).first() or \
               security.User.query.filter_by(email=user).first()
    
    def _do_find_role(self, role):
        return security.Role.query.filter_by(name=role).first()
    