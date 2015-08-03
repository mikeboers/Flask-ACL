from . import *

from flask_acl.core import check


class TestCoreCheck(FlaskTestCase):

    def test_empty(self):
        self.assertIs(None, check('permission', []))

    def test_always_allow(self):
        with self.client:
            self.client.get('/')
            self.assertIs(True, check('permission', '''
                ALLOW ANY ALL
            '''))

    def test_always_deny(self):
        with self.client:
            self.client.get('/')
            self.assertIs(False, check('permission', '''
                DENY ANY ALL
            '''))
