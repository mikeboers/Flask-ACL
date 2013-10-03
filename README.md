Flask-ACL
=========

Configurable access control lists for Flask.


Overview
--------

An access control list (ACL) is a list of access control elements (ACE). An ACE is a 3-tuple of:

1. whether to allow or deny the permission
2. a predicate which determines if the ACE matches the authentication context;
3. a set of permissions that this rule applies to.

To determine if the current user has a given permission on a given object in a given context, we iterate through the ACEs in the ACL of the object, testing each to see if the predicate is true in the context and the requested permission is in those that the ACE applies to. If both those conditions are met, the requested permission is either allowed or denied, as determined by the rule.

For example, an English version of an ACL may be:

- allow root any permission;
- allow group admins to write;
- allow group members to read;
- deny everyone any permission.

That ACL could be represented by:

~~~
[
    ('ALLOW', Role('wheel'), AnyPermission),
    ('ALLOW', lambda user, group, **kw: user in group.members and user.is_admin, set(['write'])),
    ('ALLOW', lambda user, group, **kw: user in group.members, set(['read'])),
    ('DENY', Anyone, AnyPermission),
]
~~~


### Permissions

A "permission" is a single object that represents an action that a user may want to take. This can be a string, tuple, anyting, but usually I use strings such as `"group.read"` and `"group.write"`.

A "permission set" is any object that supports the `__contains__` interface. In Python, a permission set contains a permission if `permission in permission_set` is true.


### Predicates

A "predicate" is a test against the authentication context, and returns a truth value. These are implemented as callables that take the context as keyword arguments.

Several predefined predicates check for authenticated users, local users, anonymouse users, or if a user has a given principal (e.g. email or username).


### Access Control Elements

An ACE is a tuple of a truth value, a predicate, and a permission set. If the predicate matches, and the permission of interest is in the permission set, the truth value determines if the user is allowed to perform that action.

E.g.: `(Allow, ANY, 'read')` will allow anyone to `'read'` an object.


Usage
-----

Define ACLs on objects via an `__acl__` attribute (which may be a property). Defer ACLs to base objects via a iterable `__acl_bases__` attribute (which may be a property).

ACEs from the combined ACL will be checked for a requested permission in a given context.

~~~

obj.__acl__ = '''
    Allow ANY read
    Deny  ANY ANY
'''
check_permission('read', obj, **context)

