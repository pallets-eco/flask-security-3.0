Customizing Views
=================

Flask-Security bootstraps your application with various views for handling its
configured features to get you up and running as quickly as possible. However,
you'll probably want to change the way these views look to be more in line with
your application's visual design.


Views
-----

Flask-Security is packaged with a default template for each view it presents to
a user. Templates are located within a subfolder named ``security``. The
following is a list of view templates:

* `security/forgot_password.html`
* `security/login_user.html`
* `security/register_user.html`
* `security/reset_password.html`
* `security/change_password.html`
* `security/send_confirmation.html`
* `security/send_login.html`

Overriding these templates is simple:

1. Create a folder named ``security`` within your application's templates folder
2. Create a template with the same name for the template you wish to override

You can also specify custom template file paths in the :doc:`configuration <configuration>`.

Each template is passed a template context object that includes the following,
including the objects/values that are passed to the template by the main
Flask application context processor:

* ``<template_name>_form``: A form object for the view
* ``security``: The Flask-Security extension object

To add more values to the template context, you can specify a context processor
for all views or a specific view. For example::

    security = Security(app, user_datastore)

    # This processor is added to all templates
    @security.context_processor
    def security_context_processor():
        return dict(hello="world")

    # This processor is added to only the register view
    @security.register_context_processor
    def security_register_processor():
        return dict(something="else")

The following is a list of all the available context processor decorators:

* ``context_processor``: All views
* ``forgot_password_context_processor``: Forgot password view
* ``login_context_processor``: Login view
* ``register_context_processor``: Register view
* ``reset_password_context_processor``: Reset password view
* ``change_password_context_processor``: Change password view
* ``send_confirmation_context_processor``: Send confirmation view
* ``send_login_context_processor``: Send login view


Forms
-----

All forms can be overridden. For each form used, you can specify a
replacement class. This allows you to add extra fields to the
register form or override validators::

    from flask_security.forms import RegisterForm

    class ExtendedRegisterForm(RegisterForm):
        first_name = StringField('First Name', [Required()])
        last_name = StringField('Last Name', [Required()])

    security = Security(app, user_datastore,
             register_form=ExtendedRegisterForm)

For the ``register_form`` and ``confirm_register_form``, each field is
passed to the user model (as kwargs) when a user is created. In the
above case, the ``first_name`` and ``last_name`` fields are passed
directly to the model, so the model should look like::

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True)
        password = db.Column(db.String(255))
        first_name = db.Column(db.String(255))
        last_name = db.Column(db.String(255))

The following is a list of all the available form overrides:

* ``login_form``: Login form
* ``confirm_register_form``: Confirmable register form
* ``register_form``: Register form
* ``forgot_password_form``: Forgot password form
* ``reset_password_form``: Reset password form
* ``change_password_form``: Change password form
* ``send_confirmation_form``: Send confirmation form
* ``passwordless_login_form``: Passwordless login form


Emails
------

Flask-Security is also packaged with a default template for each email that it
may send. Templates are located within the subfolder named ``security/email``.
The following is a list of email templates:

* `security/email/confirmation_instructions.html`
* `security/email/confirmation_instructions.txt`
* `security/email/login_instructions.html`
* `security/email/login_instructions.txt`
* `security/email/reset_instructions.html`
* `security/email/reset_instructions.txt`
* `security/email/reset_notice.html`
* `security/email/change_notice.txt`
* `security/email/change_notice.html`
* `security/email/reset_notice.txt`
* `security/email/welcome.html`
* `security/email/welcome.txt`

Overriding these templates is simple:

1. Create a folder named ``security`` within your application's templates folder
2. Create a folder named ``email`` within the ``security`` folder
3. Create a template with the same name for the template you wish to override

Each template is passed a template context object that includes values for any
links that are required in the email. If you require more values in the
templates, you can specify an email context processor with the
``mail_context_processor`` decorator. For example::

    security = Security(app, user_datastore)

    # This processor is added to all emails
    @security.mail_context_processor
    def security_mail_processor():
        return dict(hello="world")


Emails with Celery
------------------

Sometimes it makes sense to send emails via a task queue, such as `Celery`_.
To delay the sending of emails, you can use the ``@security.send_mail_task``
decorator like so::

    # Setup the task
    @celery.task
    def send_security_email(msg):
        # Use the Flask-Mail extension instance to send the incoming ``msg`` parameter
        # which is an instance of `flask_mail.Message`
        mail.send(msg)

    @security.send_mail_task
    def delay_security_email(msg):
        send_security_email.delay(msg)

.. _Celery: http://www.celeryproject.org/
