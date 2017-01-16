from flask_security.datastore import *


class PymodmDatastore(Datastore):
    '''
    Inheritance the datastore.
    '''
    def __init__(self):
        pass
    def put(self, model):
        model.save( full_clean=False)
        # model.save()
        return model

    def delete(self, model):
        model.delete()


class PymodmUserDatastore(PymodmDatastore, UserDatastore):
    '''
    Use this to support the pymodm.

    '''


    def __init__(self,  user_model, role_model):
        PymodmDatastore.__init__(self)
        UserDatastore.__init__(self, user_model, role_model)

    def get_user(self, identifier):

        from pymodm.errors import ValidationError
        try:
            return self.user_model.objects.raw({'id':identifier}).first()
        except ValidationError:
            pass

        # for attr in get_identity_attributes():
        #     query_key = '%s__iexact' % attr
        #     query = {query_key: identifier}
        #     rv = self.user_model.objects(**query).first()
        #     if rv is not None:
        #         return rv

    def find_user(self, **kwargs):

        from pymodm.errors import ValidationError

        try:
            for k, v in kwargs:
                return self.user_model.objects.raw({k:v}).first()

        except ValidationError:  # pragma: no cover
            return None

    def find_role(self, role):

        try:
            return self.role_model.objects.raw({'name' : role}).first()
        except self.role_model.DoesNotExist:
            return None


