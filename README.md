Flask-ACL
=========

Simple access control lists for Flask.


Overview
--------

Our ACLs work are built out of permissions, predicates, and access control elements.


Permissions
^^^^^^^^^^^

A `permission` is a single object that represents an action that a user may want to take. This can be a string, tuple, anyting, but usually I use strings such as `"read"` and `"write"`.

A `permission set` is any object that supports the `__contains__` interface. More simply, a permission set contains a permission if `permission in permission_set` is true.


Predicates
^^^^^^^^^^

A `predicate` is a test against the current environment, to determine if the current user may be assigned some permissions. A predicate is any function that takes keyword arguments, and returns a truth value.

Several predefined predicates check for authenticated users, local users, anonymouse users, or if a user has a given principal (e.g. email or username).


Access Control Elements
^^^^^^^^^^^^^^^^^^^^^^^

An ACE is a tuple of a truth value, a predicate, and a permission set. If the predicate matches, and the permission of interest is in the permission set, the truth value determines if the user is allowed to perform that action.

E.g.: `(Allow, ANY, 'read')` will allow anyone to `'read'` an object.


Usage
-----

Define ACLs on objects via an `__acl__` attribute (which may be a property). Defer ACLs to the parent via a `__acl_parent__` attribute.

ACEs from the combined ACL will be checked for a requested permission in a given context.

~~~

obj.__acl__ = '''
    Allow ANY read
    Deny  ANY ANY
'''
check_permission('read', obj, **context)

