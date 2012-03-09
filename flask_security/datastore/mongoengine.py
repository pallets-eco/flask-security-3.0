from flask.ext import security
from flask.ext.security import UserMixin, RoleMixin
from flask.ext.security.datastore import UserDatastore
    
class MongoEngineUserDatastore(UserDatastore):
    """MongoEngine datastore"""
    
    def __init__(self, db):
        self.db = db
        
    def get_models(self):
        db = self.db
        
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
            
        return User, Role
    
    def _save_model(self, model):
        model.save()
        return model
        
    def _do_with_id(self, id):
        try: return security.User.objects.get(id=id)
        except: return None
    
    def _do_find_user(self, user):
        return security.User.objects(username=user).first() or \
               security.User.objects(email=user).first()
    
    def _do_find_role(self, role):
        return security.Role.objects(name=role).first()
    