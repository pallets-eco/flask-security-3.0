"""
Flask-Security
==============

Flask-Security is a Flask extension that aims to add quick and simple security
to your Flask applications.

Resources
---------

* `Documentation <http://packages.python.org/Flask-Security/>`_
* `Issue Tracker <https://github.com/mattupstate/flask-security/issues>`_
* `Source <https://github.com/mattupstate/flask-security>`_
* `Development Version
  <https://github.com/mattupstate/flask-security/raw/develop#egg=Flask-Security-dev>`_

"""

from setuptools import setup

setup(
    name='Flask-Security',
    version='1.5.0',
    url='https://github.com/mattupstate/flask-security',
    license='MIT',
    author='Matt Wright',
    author_email='matt@nobien.net',
    description='Simple security for Flask apps',
    long_description=__doc__,
    packages=[
        'flask_security'
    ],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask>=0.8',
        'Flask-Login==0.1.3',
        'Flask-Mail==0.7.3',
        'Flask-Principal==0.3.3',
        'Flask-WTF==0.8',
        'itsdangerous==0.17',
        'passlib==1.6.1',
    ],
    test_suite='nose.collector',
    tests_require=[
        'nose',
        'Flask-SQLAlchemy',
        'Flask-MongoEngine',
        'py-bcrypt',
        'simplejson'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
