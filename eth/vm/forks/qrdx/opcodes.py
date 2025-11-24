"""
QRDX Opcodes

Opcodes for QRDX VM (extends Shanghai opcodes).
"""

from eth.vm.forks.shanghai.opcodes import SHANGHAI_OPCODES

# QRDX uses the same opcodes as Shanghai
# Additional quantum-resistant operations are done via precompiles, not opcodes
QRDX_OPCODES = SHANGHAI_OPCODES
