"""
Balance-Based Stake Verification

Simple, elegant staking model: Validators must hold >= MIN_STAKE QRDX tokens
in their validator address. No smart contract registration needed.

Architecture:
- Read QRDX balance directly from state database
- Validator active if balance >= MIN_STAKE
- Validator inactive if balance < MIN_STAKE
- No complex staking contract needed
"""

import logging
from typing import List, Optional
from dataclasses import dataclass
from enum import IntEnum

from eth_typing import Address
from eth_utils import to_checksum_address, to_canonical_address

logger = logging.getLogger(__name__)


# Minimum stake required (100,000 QRDX)
MIN_STAKE = 100_000 * 10**18  # 100k QRDX in wei


class ValidatorStatus(IntEnum):
    """Validator status based on balance"""
    ACTIVE = 1
    INSUFFICIENT_STAKE = 2


@dataclass
class ValidatorInfo:
    """Validator information from balance check"""
    validator_index: int
    address: str  # Checksum address
    dilithium_public_key: bytes
    balance: int  # Current QRDX balance
    status: ValidatorStatus
    
    @property
    def has_minimum_stake(self) -> bool:
        """Check if validator has minimum required stake"""
        return self.balance >= MIN_STAKE
    
    @property
    def stake(self) -> int:
        """Return balance (stake = balance in this model)"""
        return self.balance


def verify_validator_stakes_from_state(
    state,
    validators: List[dict],
    min_stake: int = MIN_STAKE,
) -> List[ValidatorInfo]:
    """
    Verify validator stakes by checking balances directly from state.
    
    Args:
        state: State object with get_balance() method
        validators: List of validator dicts from genesis (with 'address', 'public_key', 'index')
        min_stake: Minimum required stake (defaults to MIN_STAKE)
        
    Returns:
        List of ValidatorInfo objects for validators with sufficient balance
    """
    active_validators = []
    
    for validator in validators:
        address_str = validator['address']
        index = validator['index']
        public_key_hex = validator.get('public_key', '')
        
        # Convert public key from hex
        if public_key_hex.startswith('0x'):
            public_key_hex = public_key_hex[2:]
        public_key = bytes.fromhex(public_key_hex)
        
        # Convert address to canonical format
        address = to_canonical_address(address_str)
        
        # Get balance directly from state
        balance = state.get_balance(address)
        
        # Check if validator has sufficient stake
        if balance >= min_stake:
            status = ValidatorStatus.ACTIVE
            info = ValidatorInfo(
                validator_index=index,
                address=to_checksum_address(address),
                dilithium_public_key=public_key,
                balance=balance,
                status=status,
            )
            active_validators.append(info)
            
            logger.debug(
                f"✅ Validator {index} ({to_checksum_address(address)}): "
                f"{balance / 10**18:,.0f} QRDX >= {min_stake / 10**18:,.0f} QRDX"
            )
        else:
            logger.warning(
                f"⚠️  Validator {index} ({to_checksum_address(address)}) has insufficient stake: "
                f"{balance / 10**18:,.0f} QRDX < {min_stake / 10**18:,.0f} QRDX"
            )
    
    total_stake = sum(v.balance for v in active_validators)
    logger.info(
        f"✅ Found {len(active_validators)}/{len(validators)} validators with sufficient stake "
        f"(total: {total_stake / 10**18:,.0f} QRDX)"
    )
    
    return active_validators
