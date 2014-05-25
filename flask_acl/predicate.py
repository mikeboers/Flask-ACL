from flask import request

from flask_acl.globals import current_acl_manager


def parse_predicate(input):
    
    if isinstance(input, basestring):
        negate = input.startswith('!')
        if negate:
            input = input[1:]
        predicate = current_acl_manager.predicates.get(input)
        if not predicate:
            raise ValueError('unknown predicate: %r' % input)
        if negate:
            predicate = Not(predicate)
        return predicate
    
    if isinstance(input, (tuple, list)):
        return And(parse_predicate(x) for x in input)
    
    return input


class Any(object):
    def __call__(self, **kw):
        return True
    def __repr__(self):
        return 'ANY'


class Not(object):
    def __init__(self, predicate):
        self.predicate = predicate
    def __call__(self, **kw):
        return not self.predicate(**kw)
    def __repr__(self):
        return 'NOT(%r)' % self.predicate


class And(object):

    op = all

    def __init__(self, *predicates):
        self.predicates = predicates
    def __call__(self, **kw):
        return self.op(x(**kw) for x in self.predicates)
    def __repr__(self):
        return '%s(%s)' % (self.op.__name__.upper(), ', '.join(repr(x) for x in self.predicates))


class Or(And):
    op = any


class Authenticated(object):
    def __call__(self, user, **kw):
        return user.is_authenticated()
    def __repr__(self):
        return 'AUTHENTICATED'


class Active(object):
    def __call__(self, user, **kw):
        return user.is_active()
    def __repr__(self):
        return 'ACTIVE'


class Anonymous(object):
    def __call__(self, user, **kw):
        return user.is_anonymous()
    def __repr__(self):
        return 'ANONYMOUS'


class Local(object):
    def __call__(self, **kw):
        return request.remote_addr in ('127.0.0.1', '::0', '::1')
    def __repr__(self):
        return 'LOCAL'


Remote = lambda: Not(Local())


default_predicates = {
    'ACTIVE': Active(),
    'ANONYMOUS': Anonymous(),
    'AUTHENTICATED': Authenticated(),
    'LOCAL': Local(),
    'REMOTE': Remote(),
    'ANY': Any(),
}

