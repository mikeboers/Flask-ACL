from flask_acl.acl import parse_acl
from flask_acl.permission import check_permission


def check(permission, raw_acl, **context):
    # log.debug('check for %r in %s' % (permission, pformat(context)))
    for state, predicate, permission_set in parse_acl(raw_acl):
        pred_match = predicate(**context)
        perm_match = check_permission(permission, permission_set)
        # log.debug('can %s %r(%s) %r%s' % (
        #     'ALLOW' if state else 'DENY',
        #     predicate, pred_match,
        #     permission_set,
        #     ' -> ' + ('ALLOW' if state else 'DENY') + ' ' + permission if (pred_match and perm_match) else '',
        # ))
        if pred_match and perm_match:
            return state

