from flask import request


def parse_predicate(input):
    
    if isinstance(input, basestring):
        negate = input.startswith('!')
        if negate:
            input = input[1:]
        predicate = string_predicates.get(input) or Principal(input)
        if negate:
            predicate = Not(predicate)
        return predicate
    
    if isinstance(input, (tuple, list)):
        return And(parse_predicate(x) for x in input)
    
    return input


class Any(object):
    def __call__(self):
        return True
    def __repr__(self):
        return 'ANY'


class Not(object):
    def __init__(self, predicate):
        self.predicate = parse_predicate(predicate)
    def __call__(self):
        return not self.predicate()
    def __repr__(self):
        return 'NOT(%r)' % self.predicate


class And(object):

    op = all

    def __init__(self, *predicates):
        self.predicates = [parse_predicate(x) for x in predicates]
    def __call__(self):
        return self.op(x() for x in self.predicates)
    def __repr__(self):
        return '%s(%s)' % (self.op.__name__.upper(), ', '.join(repr(x) for x in self.predicates))


class Or(And):
    op = any


class Principal(object):
    def __init__(self, principal):
        self.principal = principal
    def __call__(self):
        return self.principal in request.user_principals
    def __repr__(self):
        return 'Principal(%r)' % self.principal


class Authenticated(object):
    def __call__(self):
        return request.user_id is not None
    def __repr__(self):
        return 'AUTHENTICATED'


NotAnonymous = Authenticated
Anonymous = lambda: Not(Authenticated())


class Local(object):
    def __call__(self):
        return request.remote_addr in ('127.0.0.1', '::0', '::1')
    def __repr__(self):
        return 'LOCAL'


Remote = lambda: Not(Local())


string_predicates = {
    'ANONYMOUS': Anonymous(),
    'AUTHENTICATED': Authenticated(),
    'LOCAL': Local(),
    'REMOTE': Remote(),
    'ANY': Any(),
}

# More general predicate.
class HasPermission(object):
    def __init__(self, permission):
        self.permission = permission
    def __call__(self):
        return request.has_permission(self.permission)


        