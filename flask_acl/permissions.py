


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


def parse_permissions(input):
    if isinstance(input, basestring):
        if input in string_permissions:
            return string_permissions[input]
        return set([input])
    return input
