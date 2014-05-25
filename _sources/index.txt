Flask-ACL
=========

**Flask-ACL** is a Python package which provides configurable access control lists for Flask.

It is designed to allow for you to get started authorizing users immediately, but allows for a very high level of customization.


Getting Started
---------------

At the very minimum, you must setup a `Login Manager <https://flask-login.readthedocs.org/en/latest/>`_, ``SECRET_KEY``, and ``login`` view::

    from flask import Flask, render_template
    from flask.ext.login import LoginManager
    from flask.ext.acl import ACLManager

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'monkey'
    authn = LoginManager(app)
    authz = ACLManager(app)

    @app.route('/login')
    def login():
        return render_template('login.html'), 401


Then you can start attaching ACLs to your routes:

.. code-block:: python

    @app.route('/users_area')
    @authz.route_acl('''
        ALLOW AUTHENTICATED http.get
        DENY ANY ALL
    ''')
    def users_area():
        # only authenticated users will get this far


You can also check for permissions on your models by defining an ``__acl__`` attribute::

    class MyModel(object):

        __acl__ = '''
            ALLOW AUTHENTICATED ALL
            DENY ANY ALL
        '''

        # ...

    @app.route('/model/{id}')
    def show_a_model(id):
        obj = MyModel.get(id)
        if not auths.can('read', obj):
            abort(404)
        else:
            return render_template('mymodel.html', obj=obj)


Contents
--------

.. toctree::
    :maxdepth: 2

    abstract
    protocol


API Reference
-------------

.. toctree::
    :maxdepth: 2

    api/core
    api/extension
    api/globals
    api/permission
    api/predicate
    api/state



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

