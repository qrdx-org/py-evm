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
from collections import OrderedDict
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
        if self.index < 0:
            raise ValueError(f"Validator index must be >= 0, got {self.index}")
    
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
        if self.validator_index < 0:
            raise ValueError(f"Validator index must be >= 0, got {self.validator_index}")
    
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
            genesis_validators: Initial validators (can be 1-150 for testnet)
        """
        self.validators: List[Validator] = []
        self.validator_by_address: Dict[Address, Validator] = {}
        self.validator_by_pubkey: Dict[bytes, Validator] = {}
        
        if genesis_validators:
            if len(genesis_validators) < 1 or len(genesis_validators) > VALIDATOR_COUNT:
                raise ValueError(
                    f"Genesis validators must be 1-{VALIDATOR_COUNT}, "
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
    
    def get_attestations_for_inclusion(
        self,
        current_slot: int,
        max_attestations: int = 128,
    ) -> List[Attestation]:
        """
        Get attestations to include in a new block.
        
        Selects attestations from recent slots, prioritizing:
        1. Most recent slots first
        2. Deduplication by validator
        
        Args:
            current_slot: Current slot number
            max_attestations: Maximum number of attestations to include
        
        Returns:
            List of attestations for block inclusion
        """
        included = []
        seen_validators = set()
        
        # Look back at recent slots (up to 32 slots back)
        for slot in range(current_slot - 1, max(0, current_slot - 33), -1):
            if slot not in self.attestations:
                continue
            
            # Get all attestations for this slot (all block hashes)
            for block_hash, slot_attestations in self.attestations[slot].items():
                for attestation in slot_attestations:
                    # Skip if we've already included this validator
                    if attestation.validator_index in seen_validators:
                        continue
                    
                    included.append(attestation)
                    seen_validators.add(attestation.validator_index)
                    
                    if len(included) >= max_attestations:
                        return included
        
        return included


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
        # LRU cache for block weights (limit to most recent 1000 blocks)
        # Older blocks have weights persisted to database, so cache eviction is safe
        self._block_weights: OrderedDict[Hash32, int] = OrderedDict()
        self._max_cache_size: int = 1000
    
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
    
    def calculate_block_weight(
        self,
        block_hash: Hash32,
        attestations: List[Attestation],
        validator_set: ValidatorSet,
        epoch: int,
    ) -> int:
        """
        Calculate the weight of a block based on attestations.
        
        Weight is the sum of stakes of validators who attested to this block.
        Used for fork choice - heavier chain wins.
        
        Args:
            block_hash: Hash of block
            attestations: Attestations for this block
            validator_set: Validator set
            epoch: Epoch to check validator activity
        
        Returns:
            Total weight (stake) of attestations
        """
        # Check cache first (move to end for LRU)
        if block_hash in self._block_weights:
            # Move to end (most recently used)
            self._block_weights.move_to_end(block_hash)
            return self._block_weights[block_hash]
        
        total_weight = 0
        attesting_validators = set()
        
        for attestation in attestations:
            if attestation.validator_index in attesting_validators:
                continue  # Don't count twice
            
            validator = validator_set.get_validator(attestation.validator_index)
            if validator.is_active_at_epoch(epoch):
                total_weight += validator.stake
                attesting_validators.add(attestation.validator_index)
        
        # Cache the result with LRU eviction
        self._block_weights[block_hash] = total_weight
        # Evict oldest entry if cache is full
        if len(self._block_weights) > self._max_cache_size:
            self._block_weights.popitem(last=False)  # Remove oldest (FIFO/LRU)
        
        return total_weight
    
    def clear_weight_cache(self) -> None:
        """Clear cached block weights."""
        self._block_weights.clear()


class ForkChoice:
    """
    Fork choice rule for QR-PoS consensus.
    
    Implements LMD-GHOST (Latest Message Driven Greedy Heaviest Observed SubTree)
    with finality checkpoint boundary.
    """
    
    def __init__(self, finality_gadget: FinalityGadget):
        """
        Initialize fork choice.
        
        Args:
            finality_gadget: Finality gadget for checkpoint info
        """
        self.finality_gadget = finality_gadget
    
    def get_head(
        self,
        candidates: List[Tuple[Hash32, int, int]],  # (block_hash, slot, weight)
        chaindb,  # ChainDB instance for checkpoint retrieval and ancestry checking
    ) -> Optional[Hash32]:
        """
        Select canonical chain head from competing forks.
        
        Rules:
        1. Must extend from or after finalized checkpoint (reorg boundary)
        2. Choose chain with highest total weight (most attestations)
        3. Break ties by choosing block with lower hash value
        
        Args:
            candidates: List of (block_hash, slot, weight) tuples
            chaindb: ChainDB instance to check finalized checkpoint
        
        Returns:
            Hash of canonical head block, or None if no valid candidates
        """
        if not candidates:
            return None
        
        # Get finalized checkpoint
        finalized_slot, finalized_hash = chaindb.get_qrpos_finalized_checkpoint()
        
        # Filter candidates that extend from finalized checkpoint
        valid_candidates = []
        for block_hash, slot, weight in candidates:
            # Must be at or after finalized slot
            if slot < finalized_slot:
                continue
            
            # Verify ancestry: block must extend from finalized checkpoint
            if not self._extends_from_finalized(
                block_hash,
                finalized_hash,
                finalized_slot,
                chaindb
            ):
                continue
            
            valid_candidates.append((block_hash, slot, weight))
        
        if not valid_candidates:
            # No valid candidates extend finalized checkpoint
            return None
        
        # Sort by weight (descending), then by hash (ascending for tie-breaking)
        valid_candidates.sort(key=lambda x: (-x[2], x[0]))
        
        # Return heaviest chain
        return valid_candidates[0][0]
    
    def _extends_from_finalized(
        self,
        block_hash: Hash32,
        finalized_hash: Hash32,
        finalized_slot: int,
        chaindb,
    ) -> bool:
        """
        Check if a block extends from the finalized checkpoint.
        
        Walks backwards from block_hash until either:
        - We find finalized_hash (valid)
        - We reach a slot before finalized_slot (invalid)
        - We reach genesis (valid if finalized is genesis)
        
        Args:
            block_hash: Hash of block to check
            finalized_hash: Hash of finalized checkpoint
            finalized_slot: Slot of finalized checkpoint
            chaindb: ChainDB instance for ancestry lookup
        
        Returns:
            True if block extends from finalized checkpoint, False otherwise
        """
        # Special case: if finalized is genesis (slot 0, zero hash), all blocks are valid
        if finalized_slot == 0 and finalized_hash == Hash32(b'\x00' * 32):
            return True
        
        # Walk backwards from block to find finalized checkpoint
        current_hash = block_hash
        
        # Limit depth to prevent infinite loops (shouldn't need more than ~1000 blocks)
        max_depth = 10000
        depth = 0
        
        while depth < max_depth:
            # Found the finalized checkpoint - valid!
            if current_hash == finalized_hash:
                return True
            
            try:
                # Get header for current block
                header = chaindb.get_block_header_by_hash(current_hash)
                
                # Decode slot from extra_data if available
                # Format: [slot(8 bytes)][validator_index(8 bytes)][pubkey_prefix(16 bytes)]
                if len(header.extra_data) >= 8:
                    block_slot = int.from_bytes(header.extra_data[:8], 'big')
                    
                    # If we've walked back past the finalized slot without finding it, invalid
                    if block_slot < finalized_slot:
                        return False
                
                # Reached genesis without finding finalized checkpoint
                if header.block_number == 0:
                    # Valid only if finalized is also genesis
                    return finalized_slot == 0
                
                # Move to parent block
                current_hash = header.parent_hash
                depth += 1
                
            except KeyError:
                # Block not found in database - invalid
                return False
        
        # Reached max depth without resolution - conservative: reject
        return False
    
    def compare_chains(
        self,
        chain_a: Tuple[Hash32, int, int],  # (hash, slot, weight)
        chain_b: Tuple[Hash32, int, int],
    ) -> int:
        """
        Compare two competing chains.
        
        Args:
            chain_a: (block_hash, slot, weight) for chain A
            chain_b: (block_hash, slot, weight) for chain B
        
        Returns:
            1 if chain_a is preferred
            -1 if chain_b is preferred
            0 if equal (shouldn't happen with hash tie-breaking)
        """
        hash_a, slot_a, weight_a = chain_a
        hash_b, slot_b, weight_b = chain_b
        
        # Higher weight wins
        if weight_a > weight_b:
            return 1
        elif weight_a < weight_b:
            return -1
        
        # Tie-break by hash (lower hash wins)
        if hash_a < hash_b:
            return 1
        elif hash_a > hash_b:
            return -1
        
        return 0


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


class QRPoSConsensus:
    """
    Main QR-PoS consensus engine.
    
    Manages validators, attestations, and finality for the QRDX chain.
    """
    
    def __init__(
        self,
        validator_set: Optional[ValidatorSet] = None,
        genesis_time: int = 0,
    ):
        """
        Initialize consensus engine.
        
        Args:
            validator_set: Set of validators (created if None)
            genesis_time: Unix timestamp of genesis block
        """
        self.validator_set = validator_set or ValidatorSet()
        self.attestation_pool = AttestationPool()
        self.finality_gadget = FinalityGadget()
        self.fork_choice = ForkChoice(self.finality_gadget)
        self.genesis_time = genesis_time or int(time.time())
        
    def get_current_slot(self) -> int:
        """Get current slot number."""
        return compute_current_slot(self.genesis_time)
    
    def get_proposer_for_slot(self, slot: int) -> int:
        """Get validator index that should propose for this slot."""
        epoch = compute_epoch_at_slot(slot)
        active_validators = self.validator_set.get_active_validators(epoch)
        
        if not active_validators:
            raise ValueError("No active validators")
        
        # Simple round-robin for now (can be made weighted later)
        return slot % len(active_validators)
    
    def add_attestation(self, attestation: Attestation) -> None:
        """Add an attestation to the pool."""
        self.attestation_pool.add_attestation(attestation, self.validator_set)
    
    def get_attestations_for_block(
        self,
        slot: int,
        block_hash: Hash32,
    ) -> List[Attestation]:
        """Get attestations to include in a block."""
        return self.attestation_pool.get_attestations_for_slot(slot, block_hash)
    
    def process_block_finality(
        self,
        slot: int,
        block_hash: Hash32,
        attestations: List[Attestation],
    ) -> Tuple[bool, bool]:
        """Process attestations and update finality."""
        return self.finality_gadget.process_attestations(
            slot,
            block_hash,
            attestations,
            self.validator_set,
        )
    
    def calculate_block_weight(
        self,
        block_hash: Hash32,
        attestations: List[Attestation],
        epoch: int,
    ) -> int:
        """
        Calculate weight of a block for fork choice.
        
        Args:
            block_hash: Hash of block
            attestations: Attestations for the block
            epoch: Epoch number
        
        Returns:
            Total weight (stake) of attestations
        """
        return self.finality_gadget.calculate_block_weight(
            block_hash,
            attestations,
            self.validator_set,
            epoch,
        )
    
    def select_canonical_head(
        self,
        candidates: List[Tuple[Hash32, int, int]],
        chaindb,
    ) -> Optional[Hash32]:
        """
        Select canonical chain head using fork choice rule.
        
        Args:
            candidates: List of (block_hash, slot, weight) tuples
            chaindb: ChainDB instance
        
        Returns:
            Hash of canonical head, or None if no valid candidates
        """
        return self.fork_choice.get_head(candidates, chaindb)

