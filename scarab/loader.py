"""Library instance"""

import os

from ctypes import cdll
from ctypes.util import find_library


class ScarabLoader(object):

    """Library loader"""

    def __init__(self):
        """Create library instance singleton"""
        self.scarab = None

    def __call__(self):
        """Load library if not loaded before"""
        if self.scarab is None:
            lib_path = find_library('scarab')
            if lib_path is None:
                file_path = os.path.abspath(__file__)
                project_path = os.path.dirname(os.path.dirname(file_path))
                default_lib_path = 'lib/scarab/build/libscarab.so'
                lib_path = os.path.join(project_path, default_lib_path)

            self.scarab = cdll.LoadLibrary(lib_path)

        return self.scarab