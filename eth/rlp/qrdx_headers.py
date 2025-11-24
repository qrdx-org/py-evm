"""
QRDX Chain Block Headers

Block headers for QR-PoS (Quantum-Resistant Proof of Stake) consensus.
Removes PoW fields (difficulty, nonce, mix_hash) and adds validator signatures.
"""

from typing import Optional, cast
from cached_property import cached_property

from eth_typing import Address, BlockNumber, Hash32
from eth_utils import encode_hex
import rlp
from rlp.sedes import big_endian_int, binary

from eth._utils.headers import new_timestamp_from_parent
from eth.abc import BlockHeaderAPI
from eth.constants import (
    BLANK_ROOT_HASH,
    EMPTY_UNCLE_HASH,
    GENESIS_PARENT_HASH,
    ZERO_ADDRESS,
    ZERO_HASH32,
)
from eth.crypto.blake3_hash import blake3_hash_bytes
from eth.typing import HeaderParams

from .sedes import address, hash32, trie_root, uint256


class QRDXBlockHeader(rlp.Serializable, BlockHeaderAPI):
    """
    QRDX Chain block header for QR-PoS consensus.
    
    Changes from Ethereum:
    - Removed: difficulty, nonce, mix_hash (PoW fields)
    - Added: validator_index, slot, validator_signature
    - Hash: Uses BLAKE3 instead of Keccak256
    
    QR-PoS consensus:
    - 150 validators
    - 2-second slots
    - Single-slot finality
    - Dilithium signatures (3,309 bytes)
    """
    
    fields = [
        ("parent_hash", hash32),
        ("uncles_hash", hash32),  # Will be EMPTY_UNCLE_HASH (no uncles in PoS)
        ("coinbase", address),  # Validator that proposed this block
        ("state_root", trie_root),
        ("transaction_root", trie_root),
        ("receipt_root", trie_root),
        ("bloom", uint256),
        ("block_number", big_endian_int),
        ("gas_limit", big_endian_int),
        ("gas_used", big_endian_int),
        ("timestamp", big_endian_int),
        ("extra_data", binary),
        # QR-PoS specific fields
        ("slot", big_endian_int),  # Slot number (timestamp / 2 seconds)
        ("validator_index", big_endian_int),  # Index of proposing validator (0-149)
        ("validator_signature", binary),  # Dilithium signature (3,309 bytes)
    ]
    
    def __init__(
        self,
        block_number: BlockNumber,
        gas_limit: int,
        slot: int,
        validator_index: int,
        timestamp: int = None,
        coinbase: Address = ZERO_ADDRESS,
        parent_hash: Hash32 = ZERO_HASH32,
        uncles_hash: Hash32 = EMPTY_UNCLE_HASH,
        state_root: Hash32 = BLANK_ROOT_HASH,
        transaction_root: Hash32 = BLANK_ROOT_HASH,
        receipt_root: Hash32 = BLANK_ROOT_HASH,
        bloom: int = 0,
        gas_used: int = 0,
        extra_data: bytes = b"",
        validator_signature: bytes = b"",
    ) -> None:
        """
        Initialize a QRDX block header.
        
        Args:
            block_number: Block height
            gas_limit: Maximum gas per block (50,000,000)
            slot: Slot number (increments every 2 seconds)
            validator_index: Index of validator proposing this block (0-149)
            timestamp: Unix timestamp (if None, calculated from slot)
            coinbase: Validator address (receives fees)
            parent_hash: Hash of parent block
            uncles_hash: Always EMPTY_UNCLE_HASH (no uncles in PoS)
            state_root: Root of state trie
            transaction_root: Root of transactions trie
            receipt_root: Root of receipts trie
            bloom: Logs bloom filter
            gas_used: Gas consumed by transactions
            extra_data: Arbitrary data (max 32 bytes)
            validator_signature: Dilithium signature (3,309 bytes)
        """
        if timestamp is None:
            # Calculate timestamp from slot (2-second slots)
            timestamp = slot * 2
        
        # Validate validator index
        if validator_index < 0 or validator_index >= 150:
            raise ValueError(f"Validator index must be 0-149, got {validator_index}")
        
        # Validate signature size if provided
        if validator_signature and len(validator_signature) != 3309:
            raise ValueError(
                f"Validator signature must be 3,309 bytes (Dilithium), "
                f"got {len(validator_signature)}"
            )
        
        super().__init__(
            parent_hash=parent_hash,
            uncles_hash=uncles_hash,
            coinbase=coinbase,
            state_root=state_root,
            transaction_root=transaction_root,
            receipt_root=receipt_root,
            bloom=bloom,
            block_number=block_number,
            gas_limit=gas_limit,
            gas_used=gas_used,
            timestamp=timestamp,
            extra_data=extra_data,
            slot=slot,
            validator_index=validator_index,
            validator_signature=validator_signature,
        )
    
    def __str__(self) -> str:
        return (
            f"<QRDXBlockHeader #{self.block_number} "
            f"slot={self.slot} validator={self.validator_index} "
            f"{encode_hex(self.hash)[2:10]}>"
        )
    
    _hash: Optional[Hash32] = None
    
    @property
    def hash(self) -> Hash32:
        """
        Block hash using BLAKE3 (quantum-resistant).
        
        The hash includes all fields including the validator signature.
        """
        if self._hash is None:
            self._hash = Hash32(blake3_hash_bytes(rlp.encode(self)))
        return self._hash
    
    @property
    def mining_hash(self) -> Hash32:
        """
        Hash used for signing (before validator signature is added).
        
        This is what validators sign with their Dilithium keys.
        """
        # Create a QRDXMiningHeader from this header (all fields except signature)
        mining_header = QRDXMiningHeader(
            parent_hash=self.parent_hash,
            uncles_hash=self.uncles_hash,
            coinbase=self.coinbase,
            state_root=self.state_root,
            transaction_root=self.transaction_root,
            receipt_root=self.receipt_root,
            bloom=self.bloom,
            block_number=self.block_number,
            gas_limit=self.gas_limit,
            gas_used=self.gas_used,
            timestamp=self.timestamp,
            extra_data=self.extra_data,
            slot=self.slot,
            validator_index=self.validator_index,
        )
        return Hash32(blake3_hash_bytes(rlp.encode(mining_header)))
    
    @property
    def hex_hash(self) -> str:
        return encode_hex(self.hash)
    
    @property
    def is_genesis(self) -> bool:
        return self.parent_hash == GENESIS_PARENT_HASH and self.block_number == 0
    
    # PoW fields - not used in QR-PoS, raise AttributeError
    
    @property
    def difficulty(self) -> int:
        raise AttributeError("Difficulty not used in QR-PoS consensus")
    
    @property
    def nonce(self) -> bytes:
        raise AttributeError("Nonce not used in QR-PoS consensus")
    
    @property
    def mix_hash(self) -> Hash32:
        raise AttributeError("Mix hash not used in QR-PoS consensus")
    
    # EIP-1559 fields (implemented in QRDX)
    
    @property
    def base_fee_per_gas(self) -> int:
        """
        Base fee per gas (EIP-1559).
        
        For QRDX, this could be implemented in the future.
        Currently returns 0 (all transactions use gas_price).
        """
        return 0
    
    # Withdrawals (not implemented in QRDX yet)
    
    @property
    def withdrawals_root(self) -> Optional[Hash32]:
        raise AttributeError("Withdrawals not implemented in QRDX yet")
    
    # Blob fields (not implemented in QRDX yet)
    
    @property
    def blob_gas_used(self) -> int:
        raise AttributeError("Blob transactions not implemented in QRDX yet")
    
    @property
    def excess_blob_gas(self) -> int:
        raise AttributeError("Blob transactions not implemented in QRDX yet")
    
    @property
    def parent_beacon_block_root(self) -> Optional[Hash32]:
        raise AttributeError("Beacon chain integration not implemented in QRDX yet")


class QRDXMiningHeader(rlp.Serializable):
    """
    QRDX block header before validator signature is added.
    
    This is what validators sign to propose blocks.
    """
    
    fields = [
        ("parent_hash", hash32),
        ("uncles_hash", hash32),
        ("coinbase", address),
        ("state_root", trie_root),
        ("transaction_root", trie_root),
        ("receipt_root", trie_root),
        ("bloom", uint256),
        ("block_number", big_endian_int),
        ("gas_limit", big_endian_int),
        ("gas_used", big_endian_int),
        ("timestamp", big_endian_int),
        ("extra_data", binary),
        ("slot", big_endian_int),
        ("validator_index", big_endian_int),
    ]


def sign_block_header(
    mining_header: QRDXMiningHeader,
    validator_private_key: "DilithiumPrivateKey",
) -> QRDXBlockHeader:
    """
    Sign a mining header with a validator's Dilithium private key.
    
    Args:
        mining_header: Unsigned block header
        validator_private_key: Validator's Dilithium private key
    
    Returns:
        Signed block header with validator signature
    
    Example:
        >>> from eth.crypto import generate_keypair
        >>> 
        >>> private_key, public_key = generate_keypair()
        >>> mining_header = QRDXMiningHeader(
        ...     parent_hash=ZERO_HASH32,
        ...     uncles_hash=EMPTY_UNCLE_HASH,
        ...     coinbase=ZERO_ADDRESS,
        ...     state_root=BLANK_ROOT_HASH,
        ...     transaction_root=BLANK_ROOT_HASH,
        ...     receipt_root=BLANK_ROOT_HASH,
        ...     bloom=0,
        ...     block_number=1,
        ...     gas_limit=50000000,
        ...     gas_used=0,
        ...     timestamp=2,
        ...     extra_data=b'QRDX Chain',
        ...     slot=1,
        ...     validator_index=0,
        ... )
        >>> signed_header = sign_block_header(mining_header, private_key)
        >>> assert len(signed_header.validator_signature) == 3309
    """
    # Get the hash to sign
    message = blake3_hash_bytes(rlp.encode(mining_header))
    
    # Sign with Dilithium
    signature = validator_private_key.sign(message)
    
    # Create signed header
    return QRDXBlockHeader(
        parent_hash=mining_header.parent_hash,
        uncles_hash=mining_header.uncles_hash,
        coinbase=mining_header.coinbase,
        state_root=mining_header.state_root,
        transaction_root=mining_header.transaction_root,
        receipt_root=mining_header.receipt_root,
        bloom=mining_header.bloom,
        block_number=mining_header.block_number,
        gas_limit=mining_header.gas_limit,
        gas_used=mining_header.gas_used,
        timestamp=mining_header.timestamp,
        extra_data=mining_header.extra_data,
        slot=mining_header.slot,
        validator_index=mining_header.validator_index,
        validator_signature=signature,
    )


def verify_block_header_signature(
    header: QRDXBlockHeader,
    validator_public_key: bytes,
) -> bool:
    """
    Verify a block header's validator signature.
    
    Args:
        header: Block header with signature
        validator_public_key: Dilithium public key (1,952 bytes)
    
    Returns:
        True if signature is valid, False otherwise
    
    Example:
        >>> from eth.crypto import generate_keypair, verify_dilithium_signature
        >>> 
        >>> private_key, public_key = generate_keypair()
        >>> # ... create and sign header ...
        >>> is_valid = verify_block_header_signature(signed_header, public_key.to_bytes())
        >>> assert is_valid
    """
    from eth.crypto import verify_dilithium_signature
    
    # Get the message that was signed (header without signature)
    message = header.mining_hash
    
    # Verify signature
    return verify_dilithium_signature(
        message,
        header.validator_signature,
        validator_public_key,
    )
