from distutils.core import setup

setup(
    name='Flask-ACL',
    version='0.0.1',
    description='Access control lists for Flask.',
    url='http://github.com/mikeboers/Flask-ACL',
        
    author='Mike Boers',
    author_email='flask-acl@mikeboers.com',
    license='BSD-3',

    install_requires=[
        'Flask',
        'Flask-Login',
    ],

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
    ],
    
)
