"""
QRDX State

State management for QRDX VM with quantum-resistant precompiles.
"""

from eth.vm.forks.shanghai.state import ShanghaiState
from .computation import QRDXComputation


class QRDXState(ShanghaiState):
    """
    State class for QRDX VM.
    
    Extends Shanghai state with quantum-resistant precompiles.
    """
    
    computation_class = QRDXComputation
