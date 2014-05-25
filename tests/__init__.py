from unittest import TestCase

from flask.ext.acl import AuthzManager
from flask import Flask


class FlaskTestCase(TestCase):

    def setUp(self):
        self.flask = Flask('tests')
        self.authz = AuthzManager(self.flask)
        self.client = self.flask.test_client()
