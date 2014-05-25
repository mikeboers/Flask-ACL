from . import *

from flask_acl.globals import current_authz


class TestExtension(FlaskTestCase):

    def test_app_registry(self):
        self.assertIs(self.flask.authz_manager, self.authz)

    def test_current_authz(self):
        with self.flask.test_request_context('/'):
            self.assertIs(current_authz._get_current_object(), self.authz)

