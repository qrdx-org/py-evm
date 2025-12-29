import sys

from importlib.metadata import (
    version as __version,
    PackageNotFoundError,
)

from eth.chains import (
    Chain,
    MainnetChain,
    MainnetTesterChain,
    RopstenChain,
)

#
#  Ensure we can reach 1024 frames of recursion
#
EVM_RECURSION_LIMIT = 1024 * 12
sys.setrecursionlimit(max(EVM_RECURSION_LIMIT, sys.getrecursionlimit()))


try:
    __version__ = __version("py-evm")
except PackageNotFoundError:
    # Fallback for editable installs without proper metadata
    __version__ = "0.12.1b1"
