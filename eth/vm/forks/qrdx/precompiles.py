"""
QRDX Precompiled Contracts

Quantum-resistant cryptography precompiles for smart contracts.

Address Assignments:
- 0x09: Dilithium signature verification
- 0x0a: Kyber key encapsulation
- 0x0b: Kyber decapsulation
- 0x0c: BLAKE3 hashing
"""

from eth.vm.computation import BaseComputation
from eth_typing import Address
from eth_utils import ValidationError

from eth.crypto import (
    verify_dilithium_signature,
    kyber_encapsulate,
    kyber_decapsulate,
    blake3_hash_bytes,
)


# Precompile addresses
DILITHIUM_VERIFY_ADDRESS = Address(b'\x00' * 19 + b'\x09')
KYBER_ENCAPSULATE_ADDRESS = Address(b'\x00' * 19 + b'\x0a')
KYBER_DECAPSULATE_ADDRESS = Address(b'\x00' * 19 + b'\x0b')
BLAKE3_HASH_ADDRESS = Address(b'\x00' * 19 + b'\x0c')


class DilithiumVerifyPrecompile:
    """
    Precompile 0x09: Dilithium signature verification
    
    Input format (5,293 bytes):
        - message_hash (32 bytes): BLAKE3 hash of message
        - public_key (1,952 bytes): Dilithium public key
        - signature (3,309 bytes): Dilithium signature
    
    Output:
        - success (1 byte): 0x01 if valid, 0x00 if invalid
    
    Gas cost: 50,000 (expensive due to PQ operations)
    """
    
    @staticmethod
    def gas_cost(computation: BaseComputation) -> int:
        """Gas cost for Dilithium verification."""
        return 50_000
    
    @staticmethod
    def execute(computation: BaseComputation) -> BaseComputation:
        """Execute Dilithium signature verification."""
        input_data = computation.msg.data
        
        # Validate input length
        if len(input_data) != 5293:  # 32 + 1952 + 3309
            computation.output = b'\x00'
            return computation
        
        # Parse input
        message_hash = input_data[0:32]
        public_key = input_data[32:1984]  # 32 + 1952
        signature = input_data[1984:5293]  # 1984 + 3309
        
        # Verify signature
        try:
            is_valid = verify_dilithium_signature(
                message_hash,
                signature,
                public_key,
            )
            
            computation.output = b'\x01' if is_valid else b'\x00'
        except Exception:
            computation.output = b'\x00'
        
        return computation


class KyberEncapsulatePrecompile:
    """
    Precompile 0x0a: Kyber key encapsulation
    
    Input format (1,184 bytes):
        - public_key (1,184 bytes): Kyber public key
    
    Output format (1,120 bytes):
        - ciphertext (1,088 bytes): Encapsulated key
        - shared_secret (32 bytes): Shared secret
    
    Gas cost: 30,000
    """
    
    @staticmethod
    def gas_cost(computation: BaseComputation) -> int:
        """Gas cost for Kyber encapsulation."""
        return 30_000
    
    @staticmethod
    def execute(computation: BaseComputation) -> BaseComputation:
        """Execute Kyber encapsulation."""
        input_data = computation.msg.data
        
        # Validate input length
        if len(input_data) != 1184:
            computation.output = b''
            return computation
        
        # Encapsulate
        try:
            public_key = input_data
            ciphertext, shared_secret = kyber_encapsulate(public_key)
            
            # Output: ciphertext + shared_secret
            computation.output = ciphertext + shared_secret
        except Exception:
            computation.output = b''
        
        return computation


class KyberDecapsulatePrecompile:
    """
    Precompile 0x0b: Kyber decapsulation
    
    Input format (3,680 bytes):
        - secret_key (2,592 bytes): Kyber secret key
        - ciphertext (1,088 bytes): Encapsulated key
    
    Output format (32 bytes):
        - shared_secret (32 bytes): Decapsulated shared secret
    
    Gas cost: 30,000
    """
    
    @staticmethod
    def gas_cost(computation: BaseComputation) -> int:
        """Gas cost for Kyber decapsulation."""
        return 30_000
    
    @staticmethod
    def execute(computation: BaseComputation) -> BaseComputation:
        """Execute Kyber decapsulation."""
        input_data = computation.msg.data
        
        # Validate input length
        if len(input_data) != 3680:  # 2592 + 1088
            computation.output = b''
            return computation
        
        # Parse input
        secret_key = input_data[0:2592]
        ciphertext = input_data[2592:3680]
        
        # Decapsulate
        try:
            shared_secret = kyber_decapsulate(ciphertext, secret_key)
            computation.output = shared_secret
        except Exception:
            computation.output = b''
        
        return computation


class Blake3HashPrecompile:
    """
    Precompile 0x0c: BLAKE3 hashing
    
    Input format (variable):
        - data (any length): Data to hash
    
    Output format (32 bytes):
        - hash (32 bytes): BLAKE3-256 hash
    
    Gas cost: 60 + 12 per word (same as SHA256)
    """
    
    @staticmethod
    def gas_cost(computation: BaseComputation) -> int:
        """Gas cost for BLAKE3 hashing."""
        data_size = len(computation.msg.data)
        word_count = (data_size + 31) // 32  # Round up to nearest word
        return 60 + 12 * word_count
    
    @staticmethod
    def execute(computation: BaseComputation) -> BaseComputation:
        """Execute BLAKE3 hashing."""
        input_data = computation.msg.data
        
        try:
            hash_output = blake3_hash_bytes(input_data)
            computation.output = hash_output
        except Exception:
            computation.output = b''
        
        return computation


# Precompile registry
QRDX_PRECOMPILES = {
    DILITHIUM_VERIFY_ADDRESS: DilithiumVerifyPrecompile,
    KYBER_ENCAPSULATE_ADDRESS: KyberEncapsulatePrecompile,
    KYBER_DECAPSULATE_ADDRESS: KyberDecapsulatePrecompile,
    BLAKE3_HASH_ADDRESS: Blake3HashPrecompile,
}
