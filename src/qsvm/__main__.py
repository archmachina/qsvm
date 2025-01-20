import sys
import os

# Put our parent directory in the search path incase we're not called as a module
# but __main__.py is directly called from the systemd unit, this way
# we can find resolve the other imports correctly
try:
    sys.path.insert(0, os.path.realpath(f"{os.path.dirname(__file__)}/.."))
except NameError as e:
    pass

import qsvm.cli

if __name__ == "__main__":
    qsvm.cli.main()
