import os

# If this file is somewhere/tests/scripts/foo.py, load the real code from
# somewhere/scripts/foo.py.
_REAL_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                          os.path.basename(os.path.dirname(__file__)),
                          os.path.basename(__file__))
exec(open(_REAL_FILE).read())

# The sole purpose of the following assignment is to tell Pylint that
# the module defines this name.
ConfigFile = ConfigFile
