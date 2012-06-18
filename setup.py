"""
Flask-Security
--------------

Flask-Security is a Flask extension that aims to add quick and simple security
via Flask-Login, Flask-Principal, Flask-WTF, and passlib.

Links
`````

* `development version
  <https://github.com/mattupstate/flask-security/raw/develop#egg=Flask-Security-dev>`_

"""

from setuptools import setup

setup(
    name='Flask-Security',
    version='1.3.0-dev',
    url='https://github.com/mattupstate/flask-security',
    license='MIT',
    author='Matthew Wright',
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
        'Flask-Principal==0.2',
        'Flask-WTF==0.5.4',
        'Flask-Mail==0.6.1',
        'passlib==1.5.3'
    ],
    test_suite='nose.collector',
    tests_require=[
        'nose',
        'Flask-SQLAlchemy',
        'Flask-MongoEngine',
        'py-bcrypt'
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
