#!/usr/bin/env python

from distutils.core import setup

with open('README.txt') as file:
    long_description = file.read()

setup(
        name='nirvanacli',
        version='0.0.1',
        description=(
                'Command line interface for the Nirvana task manager '
                '(nirvanahq.com)'),
        long_description=long_description,
        author='Nick Wilson',
        author_email='nick at njwilson net',
        url='http://github.com/njwilson/nirvana-cli',
        packages=['nirvana', 'nirvanacli'],
        scripts=['scripts/nirvana'],
        classifiers=[
                'Development Status :: 1 - Planning',
                'Environment :: Console',
                'Environment :: Web Environment',
                'Intended Audience :: Developers',
                'Intended Audience :: End Users/Desktop',
                'Topic :: Internet :: WWW/HTTP',
                'License :: OSI Approved :: Apache Software License',
                'Natural Language :: English',
                'Operating System :: OS Independent',
                'Programming Language :: Python',
                'Programming Language :: Python :: 2.7',
            ],
        license='Apache',
    )
