"""
QRDX Chain Quantum-Resistant Transactions

Implements transaction types with Dilithium signatures for quantum resistance.
These transactions are larger than legacy ECDSA transactions but provide
security against quantum computer attacks.

Transaction sizes:
- Legacy (ECDSA): ~110 bytes
- QRDX (Dilithium): ~5,300 bytes

The size increase is acceptable given QRDX Chain's 2-second block time
and 50M gas limit.
"""

from typing import Optional, Tuple, Sequence
from cached_property import cached_property

from eth_typing import Address, Hash32
from eth_utils import ValidationError, int_to_big_endian
import rlp
from rlp.sedes import big_endian_int, binary

from eth.abc import (
    SignedTransactionAPI,
    TransactionBuilderAPI,
    UnsignedTransactionAPI,
    ComputationAPI,
    SetCodeAuthorizationAPI,
)
from eth._utils.transactions import (
    validate_transaction_signature,
    extract_transaction_sender,
    calculate_intrinsic_gas,
    IntrinsicGasSchedule,
)
from eth.constants import CREATE_CONTRACT_ADDRESS
from eth.crypto.blake3_hash import blake3_hash_bytes
from .sedes import address


# QRDX transaction type ID
QRDX_TX_TYPE = 0x7f  # Type 127


class QRDXUnsignedTransaction(rlp.Serializable, UnsignedTransactionAPI):
    """
    Unsigned QRDX transaction (before signing with Dilithium).
    """
    
    fields = [
        ("nonce", big_endian_int),
        ("gas_price", big_endian_int),
        ("gas", big_endian_int),
        ("to", address),
        ("value", big_endian_int),
        ("data", binary),
        ("chain_id", big_endian_int),
    ]
    
    def validate(self) -> None:
        """Basic validation of transaction fields."""
        if self.gas < 21000:
            raise ValidationError("Gas too low")
        if self.gas_price < 0:
            raise ValidationError("Gas price cannot be negative")
        if self.value < 0:
            raise ValidationError("Value cannot be negative")
    
    @property
    def intrinsic_gas(self) -> int:
        """Calculate intrinsic gas cost."""
        schedule = IntrinsicGasSchedule(
            gas_tx=21000,
            gas_txcreate=32000,
            gas_txdatazero=4,
            gas_txdatanonzero=16,
        )
        return calculate_intrinsic_gas(schedule, self)
    
    def get_intrinsic_gas(self) -> int:
        """Get intrinsic gas cost (required by UnsignedTransactionAPI)."""
        return self.intrinsic_gas
    
    def as_signed_transaction(
        self,
        private_key: "DilithiumPrivateKey",
        chain_id: Optional[int] = None,
    ) -> "QRDXTransaction":
        """
        Sign this unsigned transaction.
        
        Args:
            private_key: Dilithium private key for signing
            chain_id: Optional chain ID (uses transaction's chain_id if not provided)
        
        Returns:
            Signed QRDX transaction
        """
        return sign_qrdx_transaction(self, private_key)
    
    def gas_used_by(self, computation: ComputationAPI) -> int:
        return self.intrinsic_gas + computation.get_gas_used()
    
    @property
    def access_list(self):
        return []


class QRDXTransaction(rlp.Serializable, SignedTransactionAPI, TransactionBuilderAPI):
    """
    Signed QRDX transaction with Dilithium signature.
    
    Structure:
    - Standard transaction fields (nonce, gas, to, value, data)
    - chain_id for replay protection
    - public_key (1,952 bytes) - Dilithium public key
    - signature (3,309 bytes) - Dilithium signature
    
    Total size: ~5.3 KB per transaction
    """
    
    fields = [
        ("nonce", big_endian_int),
        ("gas_price", big_endian_int),
        ("gas", big_endian_int),
        ("to", address),
        ("value", big_endian_int),
        ("data", binary),
        ("chain_id", big_endian_int),
        ("public_key", binary),  # 1,952 bytes
        ("signature", binary),   # 3,309 bytes
    ]
    
    type_id: Optional[int] = QRDX_TX_TYPE
    
    @cached_property
    def sender(self) -> Address:
        """Extract sender address from Dilithium public key."""
        return self.get_sender()
    
    @property
    def hash(self) -> Hash32:
        """Transaction hash using BLAKE3."""
        return Hash32(blake3_hash_bytes(rlp.encode(self)))
    
    @property
    def intrinsic_gas(self) -> int:
        """
        Calculate intrinsic gas cost.
        
        QRDX transactions have higher base cost due to larger signatures.
        """
        schedule = IntrinsicGasSchedule(
            gas_tx=30000,  # Higher base cost for PQ signature verification
            gas_txcreate=40000,
            gas_txdatazero=4,
            gas_txdatanonzero=16,
        )
        return calculate_intrinsic_gas(schedule, self)
    
    def gas_used_by(self, computation: ComputationAPI) -> int:
        return self.intrinsic_gas + computation.get_gas_used()
    
    @property
    def access_list(self):
        return []
    
    # SignedTransactionAPI implementation
    
    def validate(self) -> None:
        """
        Validate transaction including signature verification.
        """
        if self.gas < self.intrinsic_gas:
            raise ValidationError(f"Insufficient gas: {self.gas} < {self.intrinsic_gas}")
        
        # Validate signature
        self.check_signature_validity()
    
    def check_signature_validity(self) -> None:
        """Verify Dilithium signature."""
        validate_transaction_signature(self)
    
    @property
    def is_signature_valid(self) -> bool:
        """Check if signature is valid."""
        try:
            self.check_signature_validity()
            return True
        except ValidationError:
            return False
    
    def get_sender(self) -> Address:
        """Extract sender address from public key."""
        return extract_transaction_sender(self)
    
    def get_message_for_signing(self) -> bytes:
        """
        Get the message that was signed.
        
        For QRDX transactions, this is RLP(transaction fields without signature).
        Note: public_key is NOT included in the signed message since it's derived
        from the private key that creates the signature.
        """
        unsigned_parts = [
            self.nonce,
            self.gas_price,
            self.gas,
            self.to,
            self.value,
            self.data,
            self.chain_id,
        ]
        return rlp.encode(unsigned_parts)
    
    def get_intrinsic_gas(self) -> int:
        """Get intrinsic gas cost."""
        return self.intrinsic_gas
    
    # TransactionBuilderAPI implementation
    
    @classmethod
    def create_unsigned_transaction(
        cls,
        *,
        nonce: int,
        gas_price: int,
        gas: int,
        to: Address,
        value: int,
        data: bytes,
        chain_id: int,
    ) -> QRDXUnsignedTransaction:
        """Create an unsigned QRDX transaction."""
        return QRDXUnsignedTransaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to,
            value=value,
            data=data,
            chain_id=chain_id,
        )
    
    @classmethod
    def new_transaction(
        cls,
        nonce: int,
        gas_price: int,
        gas: int,
        to: Address,
        value: int,
        data: bytes,
        chain_id: int,
        public_key: bytes,
        signature: bytes,
    ) -> "QRDXTransaction":
        """
        Create a new signed QRDX transaction.
        
        Args:
            nonce: Transaction nonce
            gas_price: Gas price in wei
            gas: Gas limit
            to: Recipient address (CREATE_CONTRACT_ADDRESS for contract creation)
            value: Value in wei
            data: Transaction data
            chain_id: Chain ID for replay protection
            public_key: Dilithium public key (1,952 bytes)
            signature: Dilithium signature (3,309 bytes)
        """
        return cls(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to,
            value=value,
            data=data,
            chain_id=chain_id,
            public_key=public_key,
            signature=signature,
        )
    
    @classmethod
    def decode(cls, encoded: bytes) -> "QRDXTransaction":
        """Decode RLP-encoded transaction."""
        return rlp.decode(encoded, sedes=cls)
    
    def encode(self) -> bytes:
        """Encode transaction as RLP."""
        return rlp.encode(self)
    
    def copy(self, **kwargs) -> "QRDXTransaction":
        """Create a copy of transaction with modified fields."""
        current_values = {
            'nonce': self.nonce,
            'gas_price': self.gas_price,
            'gas': self.gas,
            'to': self.to,
            'value': self.value,
            'data': self.data,
            'chain_id': self.chain_id,
            'public_key': self.public_key,
            'signature': self.signature,
        }
        current_values.update(kwargs)
        return self.new_transaction(**current_values)
    
    # Legacy compatibility properties (for code that expects v, r, s)
    
    @property
    def v(self) -> int:
        """Legacy v field - not used in QRDX transactions."""
        return 0
    
    @property
    def r(self) -> int:
        """Legacy r field - not used in QRDX transactions."""
        return 0
    
    @property
    def s(self) -> int:
        """Legacy s field - not used in QRDX transactions."""
        return 0
    
    @property
    def y_parity(self) -> int:
        """Legacy y_parity - not used in QRDX transactions."""
        return 0
    
    # EIP-1559 fields (not used in QRDX, but required by TransactionFieldsAPI)
    
    @property
    def max_fee_per_gas(self) -> int:
        """Return gas_price for EIP-1559 compatibility."""
        return self.gas_price
    
    @property
    def max_priority_fee_per_gas(self) -> int:
        """Return gas_price for EIP-1559 compatibility."""
        return self.gas_price
    
    @property
    def max_fee_per_blob_gas(self) -> int:
        """Not used in QRDX transactions."""
        raise AttributeError("max_fee_per_blob_gas not supported in QRDX transactions")
    
    @property
    def blob_versioned_hashes(self) -> Sequence[Hash32]:
        """Not used in QRDX transactions."""
        raise AttributeError("blob_versioned_hashes not supported in QRDX transactions")
    
    @property
    def authorization_list(self) -> Sequence[SetCodeAuthorizationAPI]:
        """Not used in QRDX transactions."""
        raise AttributeError("authorization_list not supported in QRDX transactions")
    
    def make_receipt(
        self,
        status: bytes,
        gas_used: int,
        log_entries: Tuple[Tuple[bytes, Tuple[int, ...], bytes], ...],
    ) -> "ReceiptAPI":
        """
        Build a receipt for this transaction.
        """
        from eth.vm.forks.frontier.transactions import Receipt, Log
        
        logs = [Log(address, topics, data) for address, topics, data in log_entries]
        return Receipt(
            state_root=status,
            gas_used=gas_used,
            logs=logs,
        )


def sign_qrdx_transaction(
    unsigned_tx: QRDXUnsignedTransaction,
    private_key: "DilithiumPrivateKey",
) -> QRDXTransaction:
    """
    Sign an unsigned QRDX transaction with a Dilithium private key.
    
    Args:
        unsigned_tx: The unsigned transaction
        private_key: Dilithium private key for signing
    
    Returns:
        Signed QRDX transaction
    
    Example:
        >>> from eth.crypto import generate_keypair
        >>> from eth.rlp.qrdx_transactions import QRDXTransaction, sign_qrdx_transaction
        >>> 
        >>> private_key, public_key = generate_keypair()
        >>> unsigned_tx = QRDXTransaction.create_unsigned_transaction(
        ...     nonce=0,
        ...     gas_price=1000000000,
        ...     gas=21000,
        ...     to=Address(b'\\x00' * 20),
        ...     value=1000000000000000000,
        ...     data=b'',
        ...     chain_id=1337,
        ... )
        >>> signed_tx = sign_qrdx_transaction(unsigned_tx, private_key)
        >>> assert signed_tx.is_signature_valid
    """
    from eth._utils.transactions import create_transaction_signature
    
    # Create signature
    signature = create_transaction_signature(unsigned_tx, private_key, unsigned_tx.chain_id)
    
    # Create signed transaction
    return QRDXTransaction.new_transaction(
        nonce=unsigned_tx.nonce,
        gas_price=unsigned_tx.gas_price,
        gas=unsigned_tx.gas,
        to=unsigned_tx.to,
        value=unsigned_tx.value,
        data=unsigned_tx.data,
        chain_id=unsigned_tx.chain_id,
        public_key=private_key.public_key().to_bytes(),
        signature=signature,
    )
