"""
Flask-Security
--------------

Simple security for Flask apps

Links
`````

* `development version
  <https://github.com/mattupstate/flask-security/raw/master#egg=Flask-Security-dev>`_

"""
from setuptools import setup

setup(
    name='Flask-Security',
    version='1.0.0',
    url='https://github.com/mattupstate/flask-security',
    license='MIT',
    author='Matthew Wright',
    author_email='matt@nobien.net',
    description='Simple security for Flask apps',
    long_description=__doc__,
    packages=['flask_security'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'Flask-Login',
        'Flask-Principal',
        'Flask-WTF',
        'passlib'
    ],
    test_suite='nose.collector',
    tests_require=[
        'nose',
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