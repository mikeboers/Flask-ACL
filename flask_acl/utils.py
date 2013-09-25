import logging

from .permissions import parse_permissions
from .predicates import parse_predicate


log = logging.getLogger(__name__)


def _parse_state(state):
    """Turn a bool, or string, into a bool.

    Rules:
        'Allow' -> True
        'Deny' -> False

    """
    if isinstance(state, bool):
        return bool
    state = str(state).lower()
    return dict(allow=True, deny=False)[state]


def _iter_parse_acl(acl_iter):
    """Parse a string, or list of ACE definitions, into usable ACEs."""

    if isinstance(acl_iter, basestring):
        acl_iter = [acl_iter]

    for acl in acl_iter:

        if isinstance(acl, basestring):
            aces = acl.splitlines()
            aces = [a.strip() for a in aces]
            aces = [a for a in aces if a and not a.startswith('#')]
        else:
            aces = acl

        for ace in aces:

            if isinstance(ace, basestring):
                ace = ace.split(None, 2)
            state, predicate, permissions = ace
            yield _parse_state(state), parse_predicate(predicate), parse_permissions(permissions)


def iter_object_acl(obj):
    try:
        for ace in _iter_parse_acl(getattr(obj, '__acl__')):
            yield ace
        for base in getattr(obj, '__acl_bases__'):
            for ace in iter_object_acl(base):
                yield ace
    except AttributeError:
        pass


def get_object_acl_context(obj):
    context = {}
    for base in getattr(obj, '__acl_bases__', ()):
        context.update(get_object_acl_context(base))
    context.update(getattr(obj, '__acl_context__', {}))
    return context




