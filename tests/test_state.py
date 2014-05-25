from . import *

from flask_acl.state import parse_state


class TestState(TestCase):

    def test_parsing_strings(self):
        for state, res in [
            ('Allow', True),
            ('Deny', False),
            ('Grant', True),
            ('Reject', False),
        ]:
            self.assertIs(res, parse_state(state))
            self.assertIs(res, parse_state(state.upper()))
            self.assertIs(res, parse_state(state.lower()))

    def test_parsing_invalid_state(self):
        self.assertRaises(TypeError, parse_state, 1)
        self.assertRaises(TypeError, parse_state, {})
        self.assertRaises(ValueError, parse_state, 'not a state')

