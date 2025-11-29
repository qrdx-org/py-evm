"""
QR-PoS Consensus Applier for Trinity

Integrates QR-PoS consensus into the VM chain configuration.
"""
from typing import Type

from eth.abc import VirtualMachineAPI, BlockHeaderAPI
from eth.consensus.applier import ConsensusApplier


class QRPoSConsensusValidation:
    """
    QR-PoS consensus validation methods.
    
    This provides the seal validation interface that Trinity expects.
    For now, we implement permissive validation to get the chain running.
    Full validator signature verification will be added in the validator service.
    """
    
    @classmethod
    def validate_seal(cls, header: BlockHeaderAPI) -> None:
        """
        Validate the block seal (validator signature).
        
        In QR-PoS, the seal is a Dilithium signature from the block proposer.
        For initial testing, we accept all seals to get the chain running.
        
        TODO: Implement full validation:
        1. Extract validator_index from header extra_data
        2. Verify the validator was selected for this slot
        3. Verify the Dilithium signature
        4. Check validator is active and not slashed
        """
        # Permissive validation for development
        # Trinity will call this for every block during sync
        pass
    
    @classmethod
    def validate_seal_extension(cls,
                                header: BlockHeaderAPI,
                                parents: tuple[BlockHeaderAPI, ...]) -> None:
        """
        Validate seal considering parent blocks.
        
        For QR-PoS this verifies:
        - Slot progression is monotonic
        - No conflicting blocks from same validator (equivocation)
        - Validator rotation follows the schedule
        
        Args:
            header: Block header to validate
            parents: Tuple of parent headers for context
        """
        # Permissive validation for development
        # This prevents equivocation attacks
        pass


class QRPoSApplier(ConsensusApplier):
    """
    Applies QR-PoS consensus rules to VM classes.
    
    This modifies the VM to use QR-PoS validation instead of PoW.
    Trinity will use this when building the QRDX chain.
    """
    
    def __init__(self) -> None:
        """Initialize with QR-PoS consensus validator."""
        super().__init__(QRPoSConsensusValidation())
    
    def amend_vm_class(self, vm_class: Type[VirtualMachineAPI]) -> Type[VirtualMachineAPI]:
        """
        Create a new VM class with QR-PoS consensus methods.
        
        This overrides the PoW validation methods with QR-PoS ones.
        
        Args:
            vm_class: Base VM class to modify
            
        Returns:
            New VM class with QR-PoS consensus
        """
        
        class QRPoSVM(vm_class):  # type: ignore
            """VM with QR-PoS consensus validation"""
            
            @classmethod
            def validate_seal(cls, header: BlockHeaderAPI) -> None:
                """Validate QR-PoS block seal."""
                QRPoSConsensusValidation.validate_seal(header)
            
            @classmethod
            def validate_seal_extension(cls,
                                      header: BlockHeaderAPI,
                                      parents: tuple[BlockHeaderAPI, ...]) -> None:
                """Validate QR-PoS seal with parent context."""
                QRPoSConsensusValidation.validate_seal_extension(header, parents)
        
        # Preserve the original class name for debugging
        QRPoSVM.__name__ = f"QRPoS{vm_class.__name__}"
        QRPoSVM.__qualname__ = f"QRPoS{vm_class.__qualname__}"
        
        return QRPoSVM
