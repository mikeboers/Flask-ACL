import logging

from .permissions import parse_permissions
from .predicates import parse_predicate


log = logging.getLogger(__name__)


def parse_state(state):
    """Turn a bool, or string, into a bool.

    Rules:
        'Allow' -> True
        'Deny' -> False

    """
    if isinstance(state, bool):
        return bool
    state = str(state).lower()
    return dict(allow=True, deny=False)[state]


def parse_ace(ace):
    """Parse a string, or 3-tuple into an ACE"""
    if isinstance(ace, basestring):
        ace = ace.split(None, 2)
    state, predicate, permissions = ace
    return parse_state(state), parse_predicate(predicate), parse_permissions(permissions)


def iter_parse_acl(acl):
    """Parse a string, or list of ACE definitions, into usable ACEs."""
    if isinstance(acl, basestring):
        for line in acl.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            yield parse_ace(line)
    else:
        for ace in acl:
            yield parse_ace(ace)


def ACL(*acl):
    def _ACL(func):
        func.__dict__.setdefault('__acl__', []).extend(parse_ace(x) for x in acl)
        return func
    return _ACL


def requires(*predicates):
    def _requires(func):
        func.__dict__.setdefault('__auth_predicates__', []).extend(parse_predicate(x) for x in predicates)
        return func
    return _requires


def iter_object_aces(obj):
    try:
        for ace in iter_parse_acl(getattr(obj, '__acl__')):
            yield ace
    except AttributeError:
        pass

    try:
        for ace in iter_object_aces(getattr(obj, '__acl_parent__')):
            yield ace
    except AttributeError:
        pass


def can(permission, obj, **kwargs):
    """Check if we can do something with an object.

    >>> auth.can('read', some_object)
    >>> auth.can('write', another_object, group=some_group)

    """
    for state, predicate, permissions in iter_object_aces(obj):
        predicate = parse_predicate(predicate)
        pred_match = predicate(**kwargs)
        log.info('ACE: %r %r %r -> %r' % (state, predicate, permissions, pred_match))
        if pred_match and permission in parse_permissions(permissions):
            log.info('ACE matched: %s%r via %r' % ('' if state else 'not ', permission, predicate))
            return state
    return None

