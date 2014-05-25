from . import *

from flask_acl.permission import is_permission_in_set


class TestPermissions(TestCase):

    def test_strings(self):
        self.assertTrue(is_permission_in_set('xxx', 'xxx'))
        self.assertFalse(is_permission_in_set('xxx', 'axxx'))
        self.assertFalse(is_permission_in_set('xxx', 'xxxb'))

    def test_containers(self):
        self.assertTrue(is_permission_in_set('xxx', ('a', 'xxx', 'b')))
        self.assertTrue(is_permission_in_set('xxx', ['a', 'xxx', 'b']))
        self.assertTrue(is_permission_in_set('xxx', set(['a', 'xxx', 'b'])))
        self.assertFalse(is_permission_in_set('xxx', ('a', 'b')))
        self.assertFalse(is_permission_in_set('xxx', ['a', 'b']))
        self.assertFalse(is_permission_in_set('xxx', set(['a', 'b'])))

    def test_callables(self):
        self.assertTrue(is_permission_in_set('xxx', lambda p: True))
        self.assertTrue(is_permission_in_set('xxx', lambda p: 'x' in p))
        self.assertFalse(is_permission_in_set('xxx', lambda p: 'X' in p))
