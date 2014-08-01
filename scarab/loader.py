"""Library instance"""

import os

from ctypes import cdll
from ctypes.util import find_library


class Library(object):

    """Library loader"""

    libs = {}

    lib_paths = {
        'scarab': 'libscarab.so',
        'gmp': 'libgmp.so'
    }

    def load(name):
        """Load library if not loaded before"""
        if name not in Library.libs:
            lib_path = find_library(name)
            if lib_path is None:
                file_path = os.path.abspath(__file__)
                project_path = os.path.dirname(os.path.dirname(file_path))
                default_lib_path = Library.lib_paths[name]
                lib_path = os.path.join(project_path, default_lib_path)
            Library.libs[name] = cdll.LoadLibrary(lib_path)

        return Library.libs[name]
