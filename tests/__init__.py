from unittest import TestCase

from flask.ext.acl import AuthzManager
from flask.ext.login import LoginManager
from flask import Flask


class FlaskTestCase(TestCase):

    def setUp(self):

        self.flask = Flask('tests')
        self.flask.config['SECRET_KEY'] = 'deadbeef'
        self.login = LoginManager(self.flask)
        self.authz = AuthzManager(self.flask)
        self.client = self.flask.test_client()

        @self.flask.route('/login')
        @self.authz.route_acl('ALLOW ANY ALL')
        def login():
            return 'please login', 401

