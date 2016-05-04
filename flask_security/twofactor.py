# -*- coding: utf-8 -*-
"""
    flask_security.passwordless
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security passwordless module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""
import abc
import base64
import os

import twilio
from flask import current_app as app
from werkzeug.local import LocalProxy
from twilio.rest import TwilioRestClient

from .utils import send_mail, config_value

import onetimepass

# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def send_security_token(user, method):
    """Sends the security token via email for the specified user.

    :param user: The user to send the code to
    :param method: The method in which the code will be sent ('mail' or 'sms') at the moment
    """
    token = get_totp_password(user)
    if method == 'mail':
        send_mail(config_value('TWO_FACTOR_EMAIL_SUBJECT'), user.email,
                  'two_factor_instructions', user=user, token=token)
    elif method == 'sms':
        msg = "Use this code to log in: %s" % token
        from_number = config_value('TWO_FACTOR_SMS_SERVICE_CONFIG')['PHONE_NUMBER']

        sms_sender = SmsSenderFactory.createSender(config_value('TWO_FACTOR_SMS_SERVICE'))
        sms_sender.send_sms(from_number=from_number, to_number=user.phone_number, msg=msg)

    elif method == 'google_authenticator':
        return



def get_totp_uri(user):
    """ Generate provisioning url for use with the qrcode scanner built into the app
    :param user:
    :return:
    """
    return 'otpauth://totp/emedgene:{0}?secret={1}&issuer=emedgene'.format(user.username, user.totp)

def verify_totp(user, token, window=0):
    """ Verifies token for specific user
    :param user, token
    :return:
    """
    return onetimepass.valid_totp(token, user.totp, window=window)


def get_totp_password(user):
    """Get time-based one-time password on the basis of given secret and time"""
    return onetimepass.get_totp(user.totp)


def generate_totp():
    return base64.b32encode(os.urandom(10)).decode('utf-8')



class SmsSenderBaseClass(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        pass

    @abc.abstractmethod
    def send_sms(self, from_number, to_number, msg):
        """ Abstract method for sensing sms messages"""
        return

class TwilioSmsSender(SmsSenderBaseClass):
    def __init__(self):
        self.account_sid = config_value('TWO_FACTOR_SMS_SERVICE_CONFIG')['ACCOUNT_SID']
        self.auth_token = config_value('TWO_FACTOR_SMS_SERVICE_CONFIG')['AUTH_TOKEN']

    def send_sms(self, from_number, to_number, msg):
        client = TwilioRestClient(self.account_sid, self.auth_token)
        client.messages.create(
            to=to_number,
            from_=from_number,
            body=msg,
        )

class DummySmsSender(SmsSenderBaseClass):

    def send_sms(self, from_number, to_number, msg):
        return

class SmsSenderFactory(object):
    senders = {
        'Twilio': TwilioSmsSender,
        'Dummy': DummySmsSender
    }

    @classmethod
    def createSender(cls, name, *args, **kwargs):
        return cls.senders[name](*args, **kwargs)