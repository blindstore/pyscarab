from setuptools import setup


setup (name='pyscarab',
       version='0.1',
       description='Python wrapper and abstractions for libscarab FHE library',
       author='Bogdan Kulynych, Benjamin Lipp, Davide Kirchner',
       author_email='hello@hidden-markov.com, mail@benjaminlipp.de, davide.kirchner@yahoo.it',
       url='https://github.com/blindstore/pyscarab',
       packages=['scarab', 'scarab.tests'],
       license='MIT',

       keywords='crypto',

       classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
       ],

       test_suite='nose.collector',
       test_requires=[
           'nose'
       ])
