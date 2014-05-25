Python Protocol
===============

Define ACLs on objects via an ``__acl__`` attribute. This value MUST be either a string, an interator of ACE strings, or an iterator of ACE tuples. If you provide ACE tuples permission set will not be interpreted any further, and will be used as-is.

Inherit ACLs from base objects via a iterable ``__acl_bases__`` attribute, which is a sequence of other objects to look for an ``__acl__`` on.

ACEs from the combined ACL will be checked for a requested permission in a given context.

If you wish to build your own ACL inheritance mechanism, you MUST be sure to parse ACL strings into an ACE iterator using ``flask.ext.acl.core.iter_aces(acl)``.

::

    obj.__acl__ = '''
        Allow ANY read
        Deny  ANY ANY
    '''
    check_permission('read', obj, **context)


