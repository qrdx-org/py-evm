"""
QR-PoS Block Validator

Validates blocks proposed under QR-PoS consensus.
"""

from eth_utils import ValidationError
from eth.rlp.headers import BlockHeader
from eth.crypto import DilithiumPublicKey
from eth.consensus.qrpos import SLOT_DURATION, VALIDATOR_COUNT
import rlp
import time


def decode_qrpos_extra_data(extra_data: bytes) -> dict:
    """
    Decode QR-PoS metadata from block header extra_data field.
    
    Format: [slot(8 bytes)][validator_index(8 bytes)][pubkey_prefix(16 bytes)]
    Total: 32 bytes
    """
    if len(extra_data) < 32:
        raise ValidationError(f"Invalid QR-PoS extra_data length: {len(extra_data)}, expected >= 32")
    
    slot = int.from_bytes(extra_data[0:8], 'big')
    validator_index = int.from_bytes(extra_data[8:16], 'big')
    pubkey_prefix = extra_data[16:32]
    
    return {
        'slot': slot,
        'validator_index': validator_index,
        'pubkey_prefix': pubkey_prefix,
    }


def validate_qrpos_block(
    header: BlockHeader,
    signature: bytes,
    validator_pubkeys: list,
    genesis_time: int,
) -> None:
    """
    Validate a QR-PoS block.
    
    Args:
        header: Block header to validate
        signature: Dilithium signature (3,309 bytes)
        validator_pubkeys: List of validator public key bytes
        genesis_time: Chain genesis timestamp
        
    Raises:
        ValidationError: If block is invalid
    """
    # Decode QR-PoS data from extra_data
    try:
        qrpos_data = decode_qrpos_extra_data(header.extra_data)
    except Exception as e:
        raise ValidationError(f"Failed to decode QR-PoS extra_data: {e}")
    
    slot = qrpos_data['slot']
    validator_index = qrpos_data['validator_index']
    
    # Validate proposer is correct for this slot
    # Use actual number of validators, not hardcoded VALIDATOR_COUNT
    expected_proposer = slot % len(validator_pubkeys)
    if validator_index != expected_proposer:
        raise ValidationError(
            f"Wrong proposer for slot {slot}: "
            f"expected validator {expected_proposer}, got {validator_index}"
        )
    
    # Validate validator index is within range
    if validator_index >= len(validator_pubkeys):
        raise ValidationError(
            f"Invalid validator index {validator_index}: "
            f"only {len(validator_pubkeys)} validators exist"
        )
    
    # Get validator's public key
    validator_pubkey_bytes = validator_pubkeys[validator_index]
    
    # Debug: Log public key info
    import logging
    logger = logging.getLogger('eth.consensus.qrpos_validator')
    logger.debug(
        f"Validating block #{header.block_number} from validator {validator_index}: "
        f"pubkey_len={len(validator_pubkey_bytes)}, "
        f"pubkey_hex={validator_pubkey_bytes.hex()[:64]}..., "
        f"sig_len={len(signature)}"
    )
    
    try:
        public_key = DilithiumPublicKey(validator_pubkey_bytes)
    except Exception as e:
        raise ValidationError(f"Invalid validator public key: {e}")
    
    # Verify Dilithium signature
    header_bytes = rlp.encode(header)
    try:
        if not public_key.verify(header_bytes, signature):
            raise ValidationError(
                f"Invalid Dilithium signature for block #{header.block_number} "
                f"from validator {validator_index}"
            )
    except Exception as e:
        raise ValidationError(f"Signature verification failed: {e}")
    
    # Validate slot timing (allow some clock drift)
    expected_slot = int((header.timestamp - genesis_time) // SLOT_DURATION)
    slot_diff = abs(slot - expected_slot)
    if slot_diff > 2:  # Allow up to 2 slots of drift (4 seconds)
        raise ValidationError(
            f"Invalid slot timing: header slot {slot}, "
            f"expected ~{expected_slot} based on timestamp"
        )
    
    # Validate QR-PoS specific header constraints
    if header.difficulty != 0:
        raise ValidationError(f"QR-PoS blocks must have difficulty=0, got {header.difficulty}")
    
    if header.nonce != b'\x00' * 8:
        raise ValidationError("QR-PoS blocks must have nonce=0")
    
    if header.mix_hash != b'\x00' * 32:
        raise ValidationError("QR-PoS blocks must have mix_hash=0")


def validate_qrpos_block_basic(header: BlockHeader) -> None:
    """
    Perform basic QR-PoS validation without signature verification.
    Useful for pre-validation before obtaining signatures.
    """
    # Check extra_data length
    if len(header.extra_data) < 32:
        raise ValidationError(
            f"QR-PoS blocks require extra_data >= 32 bytes, got {len(header.extra_data)}"
        )
    
    # Decode and validate basic structure
    try:
        qrpos_data = decode_qrpos_extra_data(header.extra_data)
        validator_index = qrpos_data['validator_index']
        
        if validator_index >= VALIDATOR_COUNT:
            raise ValidationError(
                f"Validator index {validator_index} exceeds maximum {VALIDATOR_COUNT}"
            )
    except Exception as e:
        raise ValidationError(f"Invalid QR-PoS extra_data: {e}")
    
    # Validate QR-PoS constraints
    if header.difficulty != 0:
        raise ValidationError("QR-PoS blocks must have difficulty=0")
    
    if header.nonce != b'\x00' * 8:
        raise ValidationError("QR-PoS blocks must have nonce=0")
