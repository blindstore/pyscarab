from setuptools import setup


setup (name='pyscarab',
       version='0.1',
       description='Python bindings for libscarab',
       author='Bogdan Kulynych',
       author_email='hello@hidden-markov.com',
       url='https://github.com/blindstore/pyscarab',
       packages=['pyscarab'],
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
       test_require=[
           'nose'
       ])
