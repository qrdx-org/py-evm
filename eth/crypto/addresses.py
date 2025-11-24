"""
QRDX Chain Address Utilities

Handles address derivation and validation for quantum-resistant addresses.
QRDX addresses are Ethereum-compatible (20 bytes) but derived using
BLAKE3 hashing of Dilithium public keys.
"""

from typing import Union
from eth_typing import Address
from eth_utils import to_bytes, is_address, to_checksum_address
from .blake3_hash import blake3_hash_to_address


def address_from_public_key(public_key: bytes) -> Address:
    """
    Derive a QRDX address from a Dilithium public key.
    
    Uses BLAKE3 hash of the public key, taking the last 20 bytes
    to maintain Ethereum address compatibility.
    
    Args:
        public_key: The Dilithium public key bytes (1,952 bytes)
    
    Returns:
        A 20-byte Address
    
    Example:
        >>> from eth.crypto import generate_keypair, address_from_public_key
        >>> _, public_key = generate_keypair()
        >>> address = address_from_public_key(public_key.to_bytes())
        >>> print(f"0x{address.hex()}")
    """
    return blake3_hash_to_address(public_key)


def is_valid_qrdx_address(address: Union[str, bytes, Address]) -> bool:
    """
    Check if an address is a valid QRDX Chain address.
    
    QRDX addresses follow Ethereum format (20 bytes / 40 hex chars).
    
    Args:
        address: The address to validate (as hex string, bytes, or Address)
    
    Returns:
        True if valid, False otherwise
    
    Example:
        >>> is_valid_qrdx_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb")
        True
        >>> is_valid_qrdx_address("0xinvalid")
        False
    """
    try:
        if isinstance(address, str):
            # Remove 0x prefix if present
            if address.startswith('0x') or address.startswith('0X'):
                address = address[2:]
            # Check if valid hex and correct length
            if len(address) != 40:
                return False
            address_bytes = to_bytes(hexstr=address)
        elif isinstance(address, (bytes, Address)):
            address_bytes = address
        else:
            return False
        
        # Must be exactly 20 bytes
        return len(address_bytes) == 20
    except Exception:
        return False


def to_qrdx_checksum_address(address: Union[str, bytes, Address]) -> str:
    """
    Convert an address to EIP-55 checksummed format.
    
    QRDX Chain uses the same checksumming as Ethereum (EIP-55)
    for address display and validation.
    
    Args:
        address: The address to checksum
    
    Returns:
        Checksummed address string with 0x prefix
    
    Raises:
        ValueError: If address is invalid
    
    Example:
        >>> address = "0x742d35cc6634c0532925a3b844bc9e7595f0beb"
        >>> to_qrdx_checksum_address(address)
        '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'
    """
    if not is_valid_qrdx_address(address):
        raise ValueError(f"Invalid QRDX address: {address}")
    
    if isinstance(address, bytes):
        address = '0x' + address.hex()
    elif not isinstance(address, str):
        address = '0x' + bytes(address).hex()
    
    # Use Ethereum's checksumming (EIP-55)
    # Note: Could implement BLAKE3-based checksumming in future for full quantum resistance
    return to_checksum_address(address)


def normalize_address(address: Union[str, bytes, Address]) -> Address:
    """
    Normalize an address to Address type (20 bytes).
    
    Args:
        address: Address in any format
    
    Returns:
        Normalized Address (20 bytes)
    
    Raises:
        ValueError: If address is invalid
    """
    if not is_valid_qrdx_address(address):
        raise ValueError(f"Invalid QRDX address: {address}")
    
    if isinstance(address, str):
        if address.startswith('0x') or address.startswith('0X'):
            address = address[2:]
        address_bytes = to_bytes(hexstr=address)
    elif isinstance(address, bytes):
        address_bytes = address
    else:
        address_bytes = bytes(address)
    
    return Address(address_bytes)


def create_contract_address(sender: Address, nonce: int) -> Address:
    """
    Generate a contract address from sender and nonce.
    
    Uses the same method as Ethereum: BLAKE3(RLP(sender, nonce))[-20:]
    
    Args:
        sender: The address creating the contract
        nonce: The sender's transaction nonce
    
    Returns:
        The contract address
    
    Note:
        This maintains compatibility with Ethereum's contract address derivation,
        but uses BLAKE3 instead of Keccak256 for quantum resistance.
    """
    import rlp
    from .blake3_hash import blake3_hash_bytes
    from rlp.sedes import big_endian_int, Binary
    
    # RLP encode sender and nonce
    rlp_encoded = rlp.encode([sender, nonce], [Binary.fixed_length(20, allow_empty=False), big_endian_int])
    
    # BLAKE3 hash and take last 20 bytes
    hash_output = blake3_hash_bytes(rlp_encoded, output_length=32)
    return Address(hash_output[-20:])


def create_contract_address2(
    sender: Address,
    salt: bytes,
    init_code_hash: bytes
) -> Address:
    """
    Generate a contract address using CREATE2 (deterministic deployment).
    
    Formula: BLAKE3(0xff ++ sender ++ salt ++ init_code_hash)[-20:]
    
    Args:
        sender: The address creating the contract
        salt: 32-byte salt
        init_code_hash: Hash of the contract init code
    
    Returns:
        The deterministic contract address
    """
    from .blake3_hash import blake3_hash_bytes
    
    if len(salt) != 32:
        raise ValueError("Salt must be exactly 32 bytes")
    if len(init_code_hash) != 32:
        raise ValueError("Init code hash must be exactly 32 bytes")
    
    # Construct: 0xff ++ sender ++ salt ++ init_code_hash
    data = b'\xff' + sender + salt + init_code_hash
    
    # BLAKE3 hash and take last 20 bytes
    hash_output = blake3_hash_bytes(data, output_length=32)
    return Address(hash_output[-20:])
