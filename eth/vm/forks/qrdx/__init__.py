"""
QRDX VM Fork

Ethereum Virtual Machine fork with quantum-resistant precompiles.

Precompiles:
- 0x09: Dilithium signature verification
- 0x0a: Kyber key encapsulation
- 0x0b: Kyber decapsulation  
- 0x0c: BLAKE3 hashing

Based on Shanghai fork but with quantum-resistant additions.
"""

from eth.vm.forks.shanghai import ShanghaiVM
from .opcodes import QRDX_OPCODES
from .state import QRDXState


class QRDXVM(ShanghaiVM):
    """
    QRDX Virtual Machine with quantum-resistant precompiles.
    
    Extends Shanghai VM with:
    - Post-quantum cryptography precompiles
    - BLAKE3 hashing
    - Modified gas costs for PQ operations
    """
    
    # Use QRDX-specific opcodes and state
    opcodes = QRDX_OPCODES
    _state_class = QRDXState
    
    fork = "qrdx"
    
    # Chain configuration
    support_dao_fork = False  # No DAO on QRDX
    support_transaction_type = True  # Support QRDX transactions
