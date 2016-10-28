Models
======

Flask-Security assumes you'll be using libraries such as SQLAlchemy,
MongoEngine or Peewee to define a data model that includes a `User` and
`Role` model. The fields on your models must follow a particular convention
depending on the functionality your app requires. Aside from this, you're
free to add any additional fields to your model(s) if you want. At the bare
minimum your `User` and `Role` model should include the following fields:

**User**

* ``id``
* ``email``
* ``password``
* ``active``


**Role**

* ``id``
* ``name``
* ``description``


Additional Functionality
------------------------

Depending on the application's configuration, additional fields may need to be
added to your `User` model.

Confirmable
^^^^^^^^^^^

If you enable account confirmation by setting your application's
`SECURITY_CONFIRMABLE` configuration value to `True`, your `User` model will
require the following additional field:

* ``confirmed_at``

Trackable
^^^^^^^^^

If you enable user tracking by setting your application's `SECURITY_TRACKABLE`
configuration value to `True`, your `User` model will require the following
additional fields:

* ``last_login_at``
* ``current_login_at``
* ``last_login_ip``
* ``current_login_ip``
* ``login_count``

Two_Factor
^^^^^^^^^^

If you enable two factor by setting your application's `TWO_FACTOR`
configuration value to `True`, your `User` model will require the following
additional fields:

* ``totp_secret``
* ``two_factor_primary_method``

If you include 'sms' in SECURITY_TWO_FACTOR_ENABLED_METHOD, your `User` model
will require the following additional field:
* ``phone_number``
