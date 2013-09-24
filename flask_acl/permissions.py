


# Permissions
class AllPermissions(object):
    def __contains__(self, other):
        return True

   
string_permissions = {
    'ALL': AllPermissions(),
}


def parse_permissions(input):
    if isinstance(input, basestring):
        if input in string_permissions:
            return string_permissions[input]
        return set([input])
    return input
