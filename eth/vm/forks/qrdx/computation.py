"""
QRDX Computation

Computation logic for QRDX VM with quantum-resistant precompiles.
"""

from eth.vm.forks.shanghai.computation import ShanghaiComputation
from .precompiles import QRDX_PRECOMPILES


class QRDXComputation(ShanghaiComputation):
    """
    Computation class for QRDX VM.
    
    Adds quantum-resistant precompiles to Shanghai computation.
    """
    
    # Merge Shanghai precompiles with QRDX precompiles
    _precompiles = dict(ShanghaiComputation._precompiles)
    _precompiles.update(QRDX_PRECOMPILES)
