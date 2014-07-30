"""Library instance"""

import os
import ctypes


path = os.path.abspath(__file__)
project_path = os.path.dirname(os.path.dirname(path))


class ScarabLoader(object):

    """Library loader"""

    def __init__(self):
        """Create library instance singleton"""
        self.scarab = None

    def __call__(self):
        """Load library if not loaded before"""
        if self.scarab is None:
            self.scarab = ctypes.cdll.LoadLibrary(os.path.join(project_path,
                'lib/scarab/build/libscarab.so'))

        return self.scarab