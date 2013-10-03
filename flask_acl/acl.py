import re

from .permission import parse_permission_set
from .predicate import parse_predicate


_state_strings = dict(
    allow=True,
    grant=True,
    deny=False,
)

def _parse_state(state):
    """Turn a bool, or string, into a bool.

    Rules:
        'Allow' -> True
        'Grant' -> True
        'Deny' -> False

    """
    if isinstance(state, bool):
        return state
    state = str(state).lower()
    return _state_strings[state]


def _iter_parse_acl(acl_iter):
    """Parse a string, or list of ACE definitions, into usable ACEs."""

    if isinstance(acl_iter, basestring):
        acl_iter = acl_iter.splitlines()
        acl_iter = [re.sub(r'#.+', '', line).strip() for line in acl_iter]
        acl_iter = filter(None, acl_iter)

    for ace in acl_iter:
        if isinstance(ace, basestring):
            ace = ace.split(None, 2)
        state, predicate, permissions = ace
        yield _parse_state(state), parse_predicate(predicate), parse_permission_set(permissions)


def iter_graph(obj, parents_first=False):

    if not parents_first:
        yield obj
    for base in getattr(obj, '__acl_bases__', ()):
        for x in iter_graph(base, parents_first):
            yield x
    if parents_first:
        yield obj


def iter_aces(root):
    """Child-first discovery of ACEs for an object.

    Walks the ACL graph via `__acl_bases__` and yields the ACEs parsed from
    `__acl__` on each object.

    """

    for obj in iter_graph(root):
        for ace in _iter_parse_acl(getattr(obj, '__acl__', ())):
            yield ace


def get_context(root):
    """Depth-first discovery of authentication context for an object.

    Walks the ACL graph via `__acl_bases__` and merges the `__acl_context__`
    attributes.

    """

    context = {}
    for obj in iter_graph(root, parents_first=True):
        context.update(getattr(obj, '__acl_context__', {}))
    return context

