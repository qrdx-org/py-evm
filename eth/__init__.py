import sys

try:
    from importlib.metadata import version as __get_version
    __version__ = __get_version("qrdx-evm")
except Exception:
    __version__ = "1.0.0-alpha.1"

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
