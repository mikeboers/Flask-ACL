import re

from .permission import parse_permission_set
from .predicate import parse_predicate


_state_strings = dict(
    allow=True,
    grant=True,
    deny=False,
)


def parse_state(state):
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


def parse_acl(acl_iter):
    """Parse a string, or list of ACE definitions, into usable ACEs."""

    if isinstance(acl_iter, basestring):
        acl_iter = [acl_iter]

    for chunk in acl_iter:

        if isinstance(chunk, basestring):
            chunk = chunk.splitlines()
            chunk = [re.sub(r'#.+', '', line).strip() for line in chunk]
            chunk = filter(None, chunk)
        else:
            chunk = [chunk]

        for ace in chunk:

            # If this was provided as a string, then parse the permission set.
            # Otherwise, use it as-is, which will result in an equality test.
            if isinstance(ace, basestring):
                ace = ace.split(None, 2)
                state, predicate, permission_set = ace
                yield parse_state(state), parse_predicate(predicate), parse_permission_set(permission_set)
            else:
                state, predicate, permission_set = ace
                yield parse_state(state), parse_predicate(predicate), permission_set



def iter_object_graph(obj, parents_first=False):

    if not parents_first:
        yield obj
    for base in getattr(obj, '__acl_bases__', ()):
        for x in iter_object_graph(base, parents_first):
            yield x
    if parents_first:
        yield obj


def iter_object_acl(root):
    """Child-first discovery of ACEs for an object.

    Walks the ACL graph via `__acl_bases__` and yields the ACEs parsed from
    `__acl__` on each object.

    """

    for obj in iter_object_graph(root):
        for ace in parse_acl(getattr(obj, '__acl__', ())):
            yield ace


def get_object_context(root):
    """Depth-first discovery of authentication context for an object.

    Walks the ACL graph via `__acl_bases__` and merges the `__acl_context__`
    attributes.

    """

    context = {}
    for obj in iter_object_graph(root, parents_first=True):
        context.update(getattr(obj, '__acl_context__', {}))
    return context

