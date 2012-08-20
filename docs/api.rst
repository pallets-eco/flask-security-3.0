API
===

Core
----
.. autoclass:: flask_security.core.Security
    :members:

.. data:: flask_security.core.current_user

   A proxy for the current user.


Protecting Views
----------------
.. autofunction:: flask_security.decorators.login_required

.. autofunction:: flask_security.decorators.roles_required

.. autofunction:: flask_security.decorators.roles_accepted

.. autofunction:: flask_security.decorators.http_auth_required

.. autofunction:: flask_security.decorators.auth_token_required


User Object Helpers
-------------------
.. autoclass:: flask_security.core.UserMixin
   :members:

.. autoclass:: flask_security.core.RoleMixin
   :members:

.. autoclass:: flask_security.core.AnonymousUser
   :members:


Datastores
----------
.. autoclass:: flask_security.datastore.UserDatastore
    :members:

.. autoclass:: flask_security.datastore.SQLAlchemyUserDatastore
    :members:
    :inherited-members:

.. autoclass:: flask_security.datastore.MongoEngineUserDatastore
    :members:
    :inherited-members:


Exceptions
----------
.. autoexception:: flask_security.exceptions.BadCredentialsError

.. autoexception:: flask_security.exceptions.AuthenticationError

.. autoexception:: flask_security.exceptions.UserNotFoundError

.. autoexception:: flask_security.exceptions.RoleNotFoundError

.. autoexception:: flask_security.exceptions.UserDatastoreError

.. autoexception:: flask_security.exceptions.UserCreationError

.. autoexception:: flask_security.exceptions.RoleCreationError

.. autoexception:: flask_security.exceptions.ConfirmationError

.. autoexception:: flask_security.exceptions.ResetPasswordError


Signals
-------
See the documentation for the signals provided by the Flask-Login and
Flask-Principal extensions. Flask-Security does not provide any additional
signals.