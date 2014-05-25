_state_strings = dict(
    allow=True,  deny=False,
    grant=True,  reject=False,
)


def parse_state(state):
    """Convert a bool, or string, into a bool.

    The string pairs we respond to (case insensitively) are:
    
    - ALLOW & DENY
    - GRANT & REJECT

    :returns bool: ``True`` or ``False``.
    :raises ValueError: when not a ``bool`` or one of the above strings.

    E.g.::

        >>> parse_state('Allow')
        True

    """
    if isinstance(state, bool):
        return state
    if not isinstance(state, basestring):
        raise TypeError('ACL state must be bool or string')
    try:
        return _state_strings[state.lower()]
    except KeyError:
        raise ValueError('unknown ACL state string')
