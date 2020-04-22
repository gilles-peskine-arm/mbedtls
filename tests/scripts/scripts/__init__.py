import os
import sys
# If this package is in 'somewhere/foo/bar/scripts', add modules
# from 'somewhere/scripts' as if they were in 'somewhere/foo/bar/scripts'.
# This way 'import scripts.thing' works whether 'thing.py' is in
# 'somewhere/foo/bar/scripts' or 'somewhere/scripts', without affecting
# the load path for imports that don't use 'scripts.'.
__path__.append(os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__path__[0]))),
    os.path.basename(__path__[0])))
