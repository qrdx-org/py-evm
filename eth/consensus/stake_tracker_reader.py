"""
StakeTracker Contract Reader for QR-PoS Consensus

This module provides a Python interface to read validator state from the
StakeTracker.sol smart contract deployed on the QRDX chain.

It enables the consensus layer to:
- Load active validators from on-chain state
- Verify validator stakes
- Query validator information by address or index
- Synchronize validator set with blockchain state

This is the critical integration layer that transforms the genesis-based
(centralized) validator loading into production-ready on-chain verification.
"""

import json
import logging
import os
from enum import IntEnum
from pathlib import Path
from typing import List, Optional, Tuple

from eth_typing import Address, HexStr
from eth_utils import to_checksum_address
from web3 import Web3
from web3.contract import Contract
from web3.exceptions import ContractLogicError
try:
    from web3.middleware import geth_poa_middleware
except ImportError:
    # web3.py >= 6.0 moved this
    try:
        from web3.middleware.geth_poa import geth_poa_middleware
    except ImportError:
        # Fallback: define no-op middleware
        geth_poa_middleware = None

logger = logging.getLogger(__name__)


class ValidatorStatus(IntEnum):
    """Validator status enum matching StakeTracker.sol"""
    PENDING = 0
    ACTIVE = 1
    EXITING = 2
    EXITED = 3
    SLASHED = 4


class ValidatorInfo:
    """Validator information structure matching StakeTracker.sol"""
    
    def __init__(
        self,
        validator_index: int,
        staker_address: Address,
        dilithium_public_key: bytes,
        stake: int,
        delegated_stake: int,
        status: ValidatorStatus,
        activation_epoch: int,
        exit_epoch: int,
        slashed: bool,
        rewards_earned: int,
        commission_rate: int,
    ):
        self.validator_index = validator_index
        self.staker_address = staker_address
        self.dilithium_public_key = dilithium_public_key
        self.stake = stake  # in Wei
        self.delegated_stake = delegated_stake  # in Wei
        self.status = status
        self.activation_epoch = activation_epoch
        self.exit_epoch = exit_epoch
        self.slashed = slashed
        self.rewards_earned = rewards_earned
        self.commission_rate = commission_rate
    
    @property
    def total_stake(self) -> int:
        """Total stake including delegations"""
        return self.stake + self.delegated_stake
    
    @property
    def is_active(self) -> bool:
        """Check if validator is currently active"""
        return self.status == ValidatorStatus.ACTIVE
    
    def __repr__(self) -> str:
        return (
            f"ValidatorInfo(index={self.validator_index}, "
            f"address={self.staker_address}, "
            f"stake={self.stake / 10**18:,.0f} QRDX, "
            f"status={self.status.name})"
        )


class StakeTrackerReader:
    """
    Interface to read validator state from StakeTracker.sol contract.
    
    This class provides the bridge between the consensus layer and the
    on-chain validator registry, enabling production-ready decentralized
    stake verification.
    
    Usage:
        reader = StakeTrackerReader(
            rpc_url="http://localhost:8545",
            contract_address="0x..."
        )
        
        # Load all active validators
        validators = reader.get_active_validators()
        
        # Verify specific validator
        is_valid = reader.verify_validator_stake(
            validator_address="0x...",
            minimum_stake=100_000 * 10**18
        )
    """
    
    MIN_STAKE = 100_000 * 10**18  # 100,000 QRDX in Wei
    MAX_VALIDATORS = 150
    
    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        timeout: int = 30,
        retry_attempts: int = 3,
    ):
        """
        Initialize StakeTracker contract reader.
        
        Args:
            rpc_url: JSON-RPC endpoint URL (e.g., http://localhost:8545)
            contract_address: Deployed StakeTracker contract address
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts for failed calls
        """
        self.rpc_url = rpc_url
        self.contract_address = to_checksum_address(contract_address)
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        
        # Initialize Web3 provider
        self.w3 = Web3(Web3.HTTPProvider(
            rpc_url,
            request_kwargs={'timeout': timeout}
        ))
        
        # Add POA middleware if needed and available (for dev/test chains)
        if geth_poa_middleware is not None:
            try:
                self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            except Exception:
                pass  # Ignore if middleware injection fails
        
        # Load contract ABI
        abi_path = Path(__file__).parent / "stake_tracker_abi.json"
        with open(abi_path) as f:
            abi = json.load(f)
        
        # Initialize contract instance
        self.contract: Contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=abi
        )
        
        # Cache for contract constants
        self._min_stake: Optional[int] = None
        self._max_validators: Optional[int] = None
        
        logger.info(
            f"StakeTrackerReader initialized: "
            f"contract={self.contract_address}, rpc={rpc_url}"
        )
    
    def is_connected(self) -> bool:
        """Check if connected to RPC endpoint"""
        try:
            return self.w3.is_connected()
        except Exception as e:
            logger.error(f"Connection check failed: {e}")
            return False
    
    def get_min_stake(self) -> int:
        """Get minimum stake requirement from contract"""
        if self._min_stake is None:
            try:
                self._min_stake = self.contract.functions.MIN_STAKE().call()
            except Exception as e:
                logger.error(f"Failed to get MIN_STAKE: {e}")
                return self.MIN_STAKE  # Fallback to hardcoded value
        return self._min_stake
    
    def get_max_validators(self) -> int:
        """Get maximum validator count from contract"""
        if self._max_validators is None:
            try:
                self._max_validators = self.contract.functions.MAX_VALIDATORS().call()
            except Exception as e:
                logger.error(f"Failed to get MAX_VALIDATORS: {e}")
                return self.MAX_VALIDATORS  # Fallback
        return self._max_validators
    
    def get_validator_count(self) -> int:
        """Get total number of registered validators"""
        try:
            return self.contract.functions.getValidatorCount().call()
        except Exception as e:
            logger.error(f"Failed to get validator count: {e}")
            raise
    
    def get_total_staked(self) -> int:
        """Get total staked amount across all validators"""
        try:
            return self.contract.functions.getTotalStaked().call()
        except Exception as e:
            logger.error(f"Failed to get total staked: {e}")
            raise
    
    def get_total_active_stake(self) -> int:
        """Get total active stake (active validators only)"""
        try:
            return self.contract.functions.getTotalActiveStake().call()
        except Exception as e:
            logger.error(f"Failed to get total active stake: {e}")
            raise
    
    def get_current_epoch(self) -> int:
        """Get current epoch from contract"""
        try:
            return self.contract.functions.getCurrentEpoch().call()
        except Exception as e:
            logger.error(f"Failed to get current epoch: {e}")
            raise
    
    def get_validator(self, validator_address: str) -> Optional[ValidatorInfo]:
        """
        Get validator information by address.
        
        Args:
            validator_address: Validator's staker address
            
        Returns:
            ValidatorInfo object or None if not found
        """
        try:
            address = to_checksum_address(validator_address)
            
            # Check if address is registered
            is_validator = self.contract.functions.isValidator(address).call()
            if not is_validator:
                logger.debug(f"{address} is not a registered validator")
                return None
            
            # Get validator info
            result = self.contract.functions.getValidator(address).call()
            
            return self._parse_validator_info(result)
            
        except ContractLogicError as e:
            logger.warning(f"Validator not found: {validator_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to get validator {validator_address}: {e}")
            raise
    
    def get_validator_by_index(self, validator_index: int) -> Optional[ValidatorInfo]:
        """
        Get validator information by index.
        
        Args:
            validator_index: Validator index (0-based)
            
        Returns:
            ValidatorInfo object or None if invalid index
        """
        try:
            result = self.contract.functions.getValidatorByIndex(validator_index).call()
            return self._parse_validator_info(result)
            
        except ContractLogicError as e:
            logger.warning(f"Invalid validator index {validator_index}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to get validator by index {validator_index}: {e}")
            raise
    
    def get_active_validators(self) -> List[ValidatorInfo]:
        """
        Get all active validators from the contract.
        
        This is the critical function for consensus layer integration.
        It replaces genesis-based validator loading with on-chain verification.
        
        Returns:
            List of ValidatorInfo objects for all active validators
        """
        try:
            logger.info("Loading active validators from StakeTracker contract...")
            
            # Get active validator indices from contract
            active_indices = self.contract.functions.getActiveValidatorIndices().call()
            
            logger.info(f"Found {len(active_indices)} active validators on-chain")
            
            # Load full validator info for each index
            validators = []
            for index in active_indices:
                validator = self.get_validator_by_index(index)
                if validator:
                    validators.append(validator)
                    logger.debug(
                        f"Loaded validator {index}: "
                        f"{validator.staker_address} "
                        f"({validator.stake / 10**18:,.0f} QRDX)"
                    )
            
            total_stake = sum(v.total_stake for v in validators)
            logger.info(
                f"Successfully loaded {len(validators)} validators "
                f"(total stake: {total_stake / 10**18:,.0f} QRDX)"
            )
            
            return validators
            
        except Exception as e:
            logger.error(f"Failed to load active validators: {e}")
            raise
    
    def verify_validator_stake(
        self,
        validator_address: str,
        minimum_stake: Optional[int] = None,
    ) -> bool:
        """
        Verify that a validator has sufficient stake on-chain.
        
        This function provides cryptographic proof that cannot be cheated
        by modifying local files.
        
        Args:
            validator_address: Validator address to check
            minimum_stake: Minimum required stake (Wei), defaults to MIN_STAKE
            
        Returns:
            True if validator is active with sufficient stake, False otherwise
        """
        if minimum_stake is None:
            minimum_stake = self.get_min_stake()
        
        try:
            validator = self.get_validator(validator_address)
            
            if not validator:
                logger.warning(f"Validator {validator_address} not registered")
                return False
            
            if validator.status != ValidatorStatus.ACTIVE:
                logger.warning(
                    f"Validator {validator_address} not active "
                    f"(status: {validator.status.name})"
                )
                return False
            
            if validator.stake < minimum_stake:
                logger.warning(
                    f"Validator {validator_address} has insufficient stake: "
                    f"{validator.stake / 10**18:,.0f} QRDX "
                    f"(minimum: {minimum_stake / 10**18:,.0f} QRDX)"
                )
                return False
            
            logger.debug(
                f"Validator {validator_address} verified: "
                f"{validator.stake / 10**18:,.0f} QRDX stake"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify validator {validator_address}: {e}")
            return False
    
    def get_active_validator_addresses(self) -> List[str]:
        """Get list of active validator addresses"""
        try:
            addresses = self.contract.functions.getActiveValidators().call()
            return [to_checksum_address(addr) for addr in addresses]
        except Exception as e:
            logger.error(f"Failed to get active validator addresses: {e}")
            raise
    
    def _parse_validator_info(self, result: Tuple) -> ValidatorInfo:
        """
        Parse validator info tuple from contract call.
        
        Contract returns:
        (
            validatorIndex,
            stakerAddress,
            dilithiumPublicKey,
            stake,
            delegatedStake,
            status,
            activationEpoch,
            exitEpoch,
            slashed,
            rewardsEarned,
            commissionRate
        )
        """
        return ValidatorInfo(
            validator_index=result[0],
            staker_address=to_checksum_address(result[1]),
            dilithium_public_key=result[2],
            stake=result[3],
            delegated_stake=result[4],
            status=ValidatorStatus(result[5]),
            activation_epoch=result[6],
            exit_epoch=result[7],
            slashed=result[8],
            rewards_earned=result[9],
            commission_rate=result[10],
        )
    
    @classmethod
    def from_env(cls) -> 'StakeTrackerReader':
        """
        Create StakeTrackerReader from environment variables.
        
        Required environment variables:
        - STAKE_TRACKER_ADDRESS: Contract address
        - QRDX_RPC_URL: JSON-RPC endpoint URL
        
        Optional:
        - RPC_TIMEOUT: Request timeout in seconds (default: 30)
        - RPC_RETRY_ATTEMPTS: Number of retry attempts (default: 3)
        """
        contract_address = os.environ.get('STAKE_TRACKER_ADDRESS')
        rpc_url = os.environ.get('QRDX_RPC_URL', 'http://localhost:8545')
        
        if not contract_address:
            raise ValueError(
                "STAKE_TRACKER_ADDRESS environment variable not set. "
                "Cannot initialize on-chain validator loading."
            )
        
        timeout = int(os.environ.get('RPC_TIMEOUT', '30'))
        retry_attempts = int(os.environ.get('RPC_RETRY_ATTEMPTS', '3'))
        
        return cls(
            rpc_url=rpc_url,
            contract_address=contract_address,
            timeout=timeout,
            retry_attempts=retry_attempts,
        )


def create_stake_tracker_reader(
    rpc_url: Optional[str] = None,
    contract_address: Optional[str] = None,
) -> Optional[StakeTrackerReader]:
    """
    Create StakeTrackerReader instance with fallback to environment variables.
    
    Args:
        rpc_url: Optional RPC URL (falls back to QRDX_RPC_URL env var)
        contract_address: Optional contract address (falls back to STAKE_TRACKER_ADDRESS)
        
    Returns:
        StakeTrackerReader instance or None if configuration missing
    """
    try:
        if contract_address and rpc_url:
            return StakeTrackerReader(
                rpc_url=rpc_url,
                contract_address=contract_address,
            )
        else:
            return StakeTrackerReader.from_env()
    except ValueError as e:
        logger.warning(f"Could not create StakeTrackerReader: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize StakeTrackerReader: {e}")
        return None
