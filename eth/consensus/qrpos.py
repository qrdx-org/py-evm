"""
QRDX Chain QR-PoS (Quantum-Resistant Proof of Stake) Consensus

Implements a BFT-based PoS consensus with:
- 150 validators
- 2-second block time (single-slot finality)
- Dilithium signatures for validator operations
- Stake-weighted validator selection
- Slashing for misbehavior

Based on principles from Ethereum 2.0 PoS but adapted for quantum resistance.
"""

from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import time

from eth_typing import Address, Hash32
from eth_utils import ValidationError

from eth.crypto import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    verify_dilithium_signature,
    blake3_hash_bytes,
)


# Consensus parameters
VALIDATOR_COUNT = 150
SLOT_DURATION = 2  # seconds
MIN_STAKE = 100_000 * 10**18  # 100,000 QRDX
SLOTS_PER_EPOCH = 32  # 64 seconds per epoch
SLASHING_PENALTY = 0.05  # 5% of stake


class ValidatorStatus(Enum):
    """Validator lifecycle states."""
    PENDING = "pending"  # Waiting to be activated
    ACTIVE = "active"  # Currently validating
    EXITING = "exiting"  # Requested exit
    SLASHED = "slashed"  # Penalized for misbehavior
    EXITED = "exited"  # No longer validating


@dataclass
class Validator:
    """
    A validator in the QRDX network.
    
    Validators propose blocks and attest to blocks proposed by others.
    """
    index: int  # Validator index (0-149)
    public_key: bytes  # Dilithium public key (1,952 bytes)
    address: Address  # Ethereum-compatible address
    stake: int  # Amount staked in wei
    status: ValidatorStatus
    activation_epoch: int  # When validator became active
    exit_epoch: Optional[int]  # When validator will exit
    slashed: bool
    
    def __post_init__(self):
        """Validate validator fields."""
        if len(self.public_key) != 1952:
            raise ValueError(f"Public key must be 1,952 bytes, got {len(self.public_key)}")
        if self.stake < MIN_STAKE:
            raise ValueError(f"Stake must be >= {MIN_STAKE}, got {self.stake}")
        if self.index < 0 or self.index >= VALIDATOR_COUNT:
            raise ValueError(f"Validator index must be 0-149, got {self.index}")
    
    def is_active_at_epoch(self, epoch: int) -> bool:
        """Check if validator is active at given epoch."""
        if self.status != ValidatorStatus.ACTIVE:
            return False
        if epoch < self.activation_epoch:
            return False
        if self.exit_epoch is not None and epoch >= self.exit_epoch:
            return False
        return True


@dataclass
class Attestation:
    """
    Validator attestation for a block.
    
    Attestations are votes for blocks and help achieve finality.
    """
    slot: int  # Slot being attested to
    block_hash: Hash32  # Hash of block being attested
    validator_index: int  # Index of attesting validator
    signature: bytes  # Dilithium signature (3,309 bytes)
    
    def __post_init__(self):
        """Validate attestation fields."""
        if len(self.signature) != 3309:
            raise ValueError(f"Signature must be 3,309 bytes, got {len(self.signature)}")
        if self.validator_index < 0 or self.validator_index >= VALIDATOR_COUNT:
            raise ValueError(f"Validator index must be 0-149, got {self.validator_index}")
    
    def get_signing_message(self) -> bytes:
        """Get the message that was signed."""
        import rlp
        
        # Encode slot + block_hash + validator_index
        data = rlp.encode([
            self.slot,
            self.block_hash,
            self.validator_index,
        ])
        
        return blake3_hash_bytes(data)


class ValidatorSet:
    """
    Manages the set of validators.
    
    Handles validator registration, activation, exit, and slashing.
    """
    
    def __init__(self, genesis_validators: Optional[List[Validator]] = None):
        """
        Initialize validator set.
        
        Args:
            genesis_validators: Initial validators (must be exactly 150)
        """
        self.validators: List[Validator] = []
        self.validator_by_address: Dict[Address, Validator] = {}
        self.validator_by_pubkey: Dict[bytes, Validator] = {}
        
        if genesis_validators:
            if len(genesis_validators) != VALIDATOR_COUNT:
                raise ValueError(
                    f"Genesis must have exactly {VALIDATOR_COUNT} validators, "
                    f"got {len(genesis_validators)}"
                )
            for validator in genesis_validators:
                self.add_validator(validator)
    
    def add_validator(self, validator: Validator) -> None:
        """Add a validator to the set."""
        if validator.index != len(self.validators):
            raise ValueError(
                f"Validator index {validator.index} doesn't match position {len(self.validators)}"
            )
        
        self.validators.append(validator)
        self.validator_by_address[validator.address] = validator
        self.validator_by_pubkey[validator.public_key] = validator
    
    def get_validator(self, index: int) -> Validator:
        """Get validator by index."""
        if index < 0 or index >= len(self.validators):
            raise ValueError(f"Invalid validator index: {index}")
        return self.validators[index]
    
    def get_validator_by_address(self, address: Address) -> Optional[Validator]:
        """Get validator by address."""
        return self.validator_by_address.get(address)
    
    def get_validator_by_pubkey(self, public_key: bytes) -> Optional[Validator]:
        """Get validator by public key."""
        return self.validator_by_pubkey.get(public_key)
    
    def get_active_validators(self, epoch: int) -> List[Validator]:
        """Get all active validators for an epoch."""
        return [
            v for v in self.validators
            if v.is_active_at_epoch(epoch)
        ]
    
    def get_total_active_stake(self, epoch: int) -> int:
        """Get total stake of active validators."""
        return sum(v.stake for v in self.get_active_validators(epoch))
    
    def slash_validator(self, index: int, reason: str) -> None:
        """
        Slash a validator for misbehavior.
        
        Args:
            index: Validator index
            reason: Reason for slashing
        """
        validator = self.get_validator(index)
        
        if validator.slashed:
            return  # Already slashed
        
        # Apply slashing penalty
        penalty = int(validator.stake * SLASHING_PENALTY)
        validator.stake -= penalty
        validator.slashed = True
        validator.status = ValidatorStatus.SLASHED
        validator.exit_epoch = compute_epoch_at_slot(
            compute_current_slot()
        ) + 1
        
        print(f"⚠️  Validator {index} slashed: {reason} (penalty: {penalty} wei)")


class ProposerSelection:
    """
    Selects block proposers for slots.
    
    Uses weighted random selection based on validator stakes.
    """
    
    @staticmethod
    def compute_proposer_index(
        slot: int,
        validators: List[Validator],
        seed: bytes = b"",
    ) -> int:
        """
        Select proposer for a slot using weighted random selection.
        
        Args:
            slot: Slot number
            validators: Active validators
            seed: Random seed (chain-specific)
        
        Returns:
            Index of selected proposer
        """
        if not validators:
            raise ValueError("No active validators")
        
        # Use slot + seed as randomness source
        import rlp
        from rlp.sedes import big_endian_int, binary, List as RLPList
        
        random_bytes = blake3_hash_bytes(
            rlp.encode([slot, seed])
        )
        random_value = int.from_bytes(random_bytes, 'big')
        
        # Weighted selection based on stake
        total_stake = sum(v.stake for v in validators)
        selection = random_value % total_stake
        
        cumulative_stake = 0
        for validator in validators:
            cumulative_stake += validator.stake
            if cumulative_stake > selection:
                return validator.index
        
        # Fallback (shouldn't reach here)
        return validators[-1].index


class AttestationPool:
    """
    Pool of pending attestations.
    
    Collects attestations from validators for inclusion in blocks.
    """
    
    def __init__(self):
        """Initialize attestation pool."""
        # slot -> block_hash -> list of attestations
        self.attestations: Dict[int, Dict[Hash32, List[Attestation]]] = {}
    
    def add_attestation(
        self,
        attestation: Attestation,
        validator_set: ValidatorSet,
    ) -> None:
        """
        Add an attestation to the pool.
        
        Args:
            attestation: Attestation to add
            validator_set: Validator set for verification
        
        Raises:
            ValidationError: If attestation is invalid
        """
        # Get validator
        validator = validator_set.get_validator(attestation.validator_index)
        
        # Verify signature
        message = attestation.get_signing_message()
        if not verify_dilithium_signature(
            message,
            attestation.signature,
            validator.public_key,
        ):
            raise ValidationError(
                f"Invalid attestation signature from validator {attestation.validator_index}"
            )
        
        # Add to pool
        if attestation.slot not in self.attestations:
            self.attestations[attestation.slot] = {}
        
        if attestation.block_hash not in self.attestations[attestation.slot]:
            self.attestations[attestation.slot][attestation.block_hash] = []
        
        self.attestations[attestation.slot][attestation.block_hash].append(attestation)
    
    def get_attestations_for_slot(
        self,
        slot: int,
        block_hash: Hash32,
    ) -> List[Attestation]:
        """Get all attestations for a specific slot and block."""
        return self.attestations.get(slot, {}).get(block_hash, [])
    
    def get_attestation_weight(
        self,
        slot: int,
        block_hash: Hash32,
        validator_set: ValidatorSet,
    ) -> int:
        """
        Get total stake weight of attestations for a block.
        
        Args:
            slot: Slot number
            block_hash: Block hash
            validator_set: Validator set
        
        Returns:
            Total stake of attesting validators
        """
        attestations = self.get_attestations_for_slot(slot, block_hash)
        epoch = compute_epoch_at_slot(slot)
        
        total_weight = 0
        for attestation in attestations:
            validator = validator_set.get_validator(attestation.validator_index)
            if validator.is_active_at_epoch(epoch):
                total_weight += validator.stake
        
        return total_weight
    
    def prune_old_attestations(self, current_slot: int, keep_slots: int = 64) -> None:
        """Remove attestations older than keep_slots."""
        cutoff_slot = current_slot - keep_slots
        slots_to_remove = [slot for slot in self.attestations if slot < cutoff_slot]
        for slot in slots_to_remove:
            del self.attestations[slot]


class FinalityGadget:
    """
    BFT finality gadget for QR-PoS.
    
    Tracks justified and finalized checkpoints based on attestations.
    """
    
    def __init__(self):
        """Initialize finality tracker."""
        self.justified_slot: int = 0
        self.justified_hash: Hash32 = Hash32(b'\x00' * 32)
        self.finalized_slot: int = 0
        self.finalized_hash: Hash32 = Hash32(b'\x00' * 32)
    
    def process_attestations(
        self,
        slot: int,
        block_hash: Hash32,
        attestations: List[Attestation],
        validator_set: ValidatorSet,
    ) -> Tuple[bool, bool]:
        """
        Process attestations and update finality status.
        
        Args:
            slot: Slot of block
            block_hash: Hash of block
            attestations: Attestations for block
            validator_set: Validator set
        
        Returns:
            (is_justified, is_finalized) tuple
        """
        epoch = compute_epoch_at_slot(slot)
        total_stake = validator_set.get_total_active_stake(epoch)
        
        # Calculate attestation weight
        attesting_stake = 0
        attesting_validators = set()
        
        for attestation in attestations:
            if attestation.validator_index in attesting_validators:
                continue  # Don't count twice
            
            validator = validator_set.get_validator(attestation.validator_index)
            if validator.is_active_at_epoch(epoch):
                attesting_stake += validator.stake
                attesting_validators.add(attestation.validator_index)
        
        # Check for supermajority (2/3 of stake)
        supermajority_threshold = (total_stake * 2) // 3
        has_supermajority = attesting_stake >= supermajority_threshold
        
        is_justified = False
        is_finalized = False
        
        if has_supermajority:
            # Justify this block
            if slot > self.justified_slot:
                self.justified_slot = slot
                self.justified_hash = block_hash
                is_justified = True
            
            # Finalize previous justified block (single-slot finality)
            if slot > self.finalized_slot:
                self.finalized_slot = slot
                self.finalized_hash = block_hash
                is_finalized = True
        
        return is_justified, is_finalized


# Utility functions

def compute_current_slot(genesis_timestamp: int = 0) -> int:
    """
    Compute current slot number.
    
    Args:
        genesis_timestamp: Unix timestamp of genesis (default: 0)
    
    Returns:
        Current slot number
    """
    current_time = int(time.time())
    elapsed = current_time - genesis_timestamp
    return elapsed // SLOT_DURATION


def compute_epoch_at_slot(slot: int) -> int:
    """
    Compute epoch number for a slot.
    
    Args:
        slot: Slot number
    
    Returns:
        Epoch number
    """
    return slot // SLOTS_PER_EPOCH


def compute_slot_at_timestamp(timestamp: int, genesis_timestamp: int = 0) -> int:
    """
    Compute slot number for a timestamp.
    
    Args:
        timestamp: Unix timestamp
        genesis_timestamp: Genesis timestamp
    
    Returns:
        Slot number
    """
    elapsed = timestamp - genesis_timestamp
    return max(0, elapsed // SLOT_DURATION)


def create_attestation(
    slot: int,
    block_hash: Hash32,
    validator_index: int,
    private_key: DilithiumPrivateKey,
) -> Attestation:
    """
    Create and sign an attestation.
    
    Args:
        slot: Slot being attested
        block_hash: Block hash
        validator_index: Index of attesting validator
        private_key: Validator's private key
    
    Returns:
        Signed attestation
    """
    import rlp
    
    # Create signing message
    data = rlp.encode([
        slot,
        block_hash,
        validator_index,
    ])
    
    message = blake3_hash_bytes(data)
    
    # Sign
    signature = private_key.sign(message)
    
    return Attestation(
        slot=slot,
        block_hash=block_hash,
        validator_index=validator_index,
        signature=signature,
    )


def verify_attestation(
    attestation: Attestation,
    validator_public_key: bytes,
) -> bool:
    """
    Verify an attestation signature.
    
    Args:
        attestation: Attestation to verify
        validator_public_key: Validator's public key
    
    Returns:
        True if valid, False otherwise
    """
    message = attestation.get_signing_message()
    return verify_dilithium_signature(
        message,
        attestation.signature,
        validator_public_key,
    )
