from distutils.core import setup, Extension

libscarab = Extension('libscarab',
                      include_dirs = ['/usr/local/include'],
                      libraries = [''],
                      library_dirs = ['/usr/local/lib'],
                      sources = [''])

setup (name='pyscarab',
       version='1.0',
       description='Python bindings for libscarab',
       author='Bogdan Kulynych',
       author_email='hello@hidden-markov.com',
       ext_modules=[libscarab])
