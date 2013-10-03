from collections import Container, Callable


# Permissions
class AllPermissions(object):
    def __contains__(self, other):
        return True
    def __repr__(self):
        return 'ANY'

   
string_permissions = {
    'ANY': AllPermissions(),
    'ALL': AllPermissions(),
    'http.get': set(('http.get', 'http.head', 'http.options')),
}


def parse_permission_set(input):
    if isinstance(input, basestring):
        if input in string_permissions:
            return string_permissions[input]
        else:
            raise ValueError('unknown permission set %r' % input)
    return input


def check_permission(perm, perm_set):

    if isinstance(perm_set, basestring):
        return perm == perm_set
    elif isinstance(perm_set, Container):
        return perm in perm_set
    elif isinstance(perm_set, Callable):
        return perm_set(perm)
    else:
        raise TypeError('permission set is not string, container, or callable')
