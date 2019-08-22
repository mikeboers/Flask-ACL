from collections import Container, Callable

from flask_acl.globals import current_acl_manager


# Permissions
class All(object):
    def __contains__(self, other):
        return True
    def __repr__(self):
        return 'ALL'

   
default_permission_sets = {
    'ALL': All(),
    'ANY': All(), # Common synonym.
    'http.get': set(('http.get', 'http.head', 'http.options')),
}


def parse_permission_set(input):
    """Lookup a permission set name in the defined permissions.

    Requires a Flask app context.

    """

    # Priority goes to the user's parsers.
    if isinstance(input, str):
        for func in current_acl_manager.permission_set_parsers:
            res = func(input)
            if res is not None:
                input = res
                break

    if isinstance(input, str):
        try:
            return current_acl_manager.permission_sets[input]
        except KeyError:
            pass

    return input


def is_permission_in_set(perm, perm_set):
    """Test if a permission is in the given set.

    :param perm: The permission object to check for.
    :param perm_set: The set to check in. If a ``str``, the permission is
        checked for equality. If a container, the permission is looked for in
        the set. If a function, the permission is passed to the "set".

    """

    if isinstance(perm_set, str):
        return perm == perm_set
    elif isinstance(perm_set, Container):
        return perm in perm_set
    elif isinstance(perm_set, Callable):
        return perm_set(perm)
    else:
        raise TypeError('permission set must be a string, container, or callable')
