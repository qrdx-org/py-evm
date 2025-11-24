"""
BLAKE3 Hashing for QRDX Chain

BLAKE3 provides quantum-resistant hashing with exceptional performance.
Output is extended to 512 bits (64 bytes) to maintain 256-bit security
against Grover's algorithm quantum attacks.

Key features:
- Quantum resistance: 256-bit effective security
- High performance: ~3x faster than SHA-256
- Extensible output: Can generate arbitrary-length hashes
- Parallelizable: Excellent for modern CPUs

Use cases in QRDX Chain:
- State roots
- Block hashes
- Merkle tree construction
- Address derivation
- Transaction hashes
"""

from typing import Union
import blake3
from eth_typing import Address, Hash32
from eth_utils import to_bytes


# Standard hash output sizes
BLAKE3_HASH_SIZE_256 = 32  # 256 bits (compatible with Hash32)
BLAKE3_HASH_SIZE_512 = 64  # 512 bits (quantum-resistant)

# For Ethereum compatibility, we use 256-bit for most operations
# But provide 512-bit version for maximum quantum resistance
DEFAULT_HASH_SIZE = BLAKE3_HASH_SIZE_256


def blake3_hash(data: Union[bytes, str], output_length: int = DEFAULT_HASH_SIZE) -> bytes:
    """
    Compute BLAKE3 hash of data.
    
    Args:
        data: The data to hash (bytes or hex string)
        output_length: Output hash length in bytes (default: 32)
    
    Returns:
        The BLAKE3 hash as bytes
    
    Example:
        >>> hash_256 = blake3_hash(b"Hello QRDX")
        >>> len(hash_256)
        32
        >>> hash_512 = blake3_hash(b"Hello QRDX", output_length=64)
        >>> len(hash_512)
        64
    """
    if isinstance(data, str):
        data = to_bytes(hexstr=data)
    
    hasher = blake3.blake3(data)
    return hasher.digest(length=output_length)


def blake3_hash_bytes(data: bytes, output_length: int = DEFAULT_HASH_SIZE) -> bytes:
    """
    Compute BLAKE3 hash of bytes (optimized version).
    
    Args:
        data: The data to hash as bytes
        output_length: Output hash length in bytes (default: 32)
    
    Returns:
        The BLAKE3 hash as bytes
    """
    hasher = blake3.blake3(data)
    return hasher.digest(length=output_length)


def blake3_hash_to_address(data: bytes) -> Address:
    """
    Hash data and convert to an Ethereum-style address.
    
    Takes BLAKE3 hash and uses last 20 bytes as address
    (similar to how Ethereum derives addresses from public keys).
    
    Args:
        data: The data to hash (typically a public key)
    
    Returns:
        An Address (20 bytes)
    
    Example:
        >>> from eth.crypto import generate_keypair
        >>> _, public_key = generate_keypair()
        >>> address = blake3_hash_to_address(public_key.to_bytes())
        >>> len(address)
        20
    """
    hash_output = blake3_hash_bytes(data, output_length=32)
    # Take last 20 bytes for address (Ethereum convention)
    return Address(hash_output[-20:])


def blake3_merkle_root(leaves: list[bytes]) -> Hash32:
    """
    Compute Merkle root using BLAKE3.
    
    Args:
        leaves: List of leaf node hashes
    
    Returns:
        The Merkle root as Hash32 (32 bytes)
    
    Raises:
        ValueError: If leaves list is empty
    """
    if not leaves:
        raise ValueError("Cannot compute Merkle root of empty list")
    
    if len(leaves) == 1:
        return Hash32(blake3_hash_bytes(leaves[0]))
    
    # Build Merkle tree bottom-up
    current_level = [blake3_hash_bytes(leaf) for leaf in leaves]
    
    while len(current_level) > 1:
        next_level = []
        
        # Process pairs
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                # Hash pair
                combined = current_level[i] + current_level[i + 1]
                next_level.append(blake3_hash_bytes(combined))
            else:
                # Odd one out, carry forward
                next_level.append(current_level[i])
        
        current_level = next_level
    
    return Hash32(current_level[0])


def blake3_incremental_hash(output_length: int = DEFAULT_HASH_SIZE):
    """
    Create an incremental BLAKE3 hasher for streaming data.
    
    Args:
        output_length: Final hash output length in bytes
    
    Returns:
        A BLAKE3 hasher object with update() and digest() methods
    
    Example:
        >>> hasher = blake3_incremental_hash()
        >>> hasher.update(b"Hello ")
        >>> hasher.update(b"World")
        >>> hash_result = hasher.digest(length=32)
    """
    return blake3.blake3()


def blake3_keyed_hash(key: bytes, data: bytes, output_length: int = DEFAULT_HASH_SIZE) -> bytes:
    """
    Compute keyed BLAKE3 hash (for MACs and PRFs).
    
    Args:
        key: The key (exactly 32 bytes required)
        data: The data to hash
        output_length: Output hash length in bytes
    
    Returns:
        The keyed hash
    
    Raises:
        ValueError: If key is not exactly 32 bytes
    """
    if len(key) != 32:
        raise ValueError("BLAKE3 keyed hash requires exactly 32-byte key")
    
    hasher = blake3.blake3(data, key=key)
    return hasher.digest(length=output_length)


def blake3_derive_key(context: str, key_material: bytes, output_length: int = 32) -> bytes:
    """
    Derive a key using BLAKE3 key derivation function.
    
    Args:
        context: Context string for domain separation
        key_material: Input key material
        output_length: Derived key length in bytes
    
    Returns:
        The derived key
    
    Example:
        >>> master_key = b"secret_key_material_here"
        >>> signing_key = blake3_derive_key("qrdx.signing", master_key)
        >>> encryption_key = blake3_derive_key("qrdx.encryption", master_key)
    """
    hasher = blake3.blake3(key_material, derive_key_context=context)
    return hasher.digest(length=output_length)
