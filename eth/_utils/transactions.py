from typing import (
    NamedTuple,
    Union,
)

from eth_utils import (
    ValidationError,
    int_to_big_endian,
)
import rlp

from eth._utils.numeric import (
    is_even,
)
from eth.abc import (
    SignedTransactionAPI,
    UnsignedTransactionAPI,
)
from eth.constants import (
    CREATE_CONTRACT_ADDRESS,
)
from eth.rlp.transactions import (
    BaseTransaction,
)
from eth.typing import (
    VRS,
    Address,
)

# QRDX Chain: Import quantum-resistant cryptography
from eth.crypto import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    verify_dilithium_signature,
    address_from_public_key,
)

EIP155_CHAIN_ID_OFFSET = 35
# Add this offset to y_parity to get "v" for legacy transactions, from Frontier
V_OFFSET = 27


def is_eip_155_signed_transaction(transaction: BaseTransaction) -> bool:
    return transaction.v >= EIP155_CHAIN_ID_OFFSET


def extract_chain_id(v: int) -> int:
    if is_even(v):
        return (v - EIP155_CHAIN_ID_OFFSET - 1) // 2
    else:
        return (v - EIP155_CHAIN_ID_OFFSET) // 2


def extract_signature_v(v: int) -> int:
    if is_even(v):
        return V_OFFSET + 1
    else:
        return V_OFFSET


def create_transaction_signature(
    unsigned_txn: UnsignedTransactionAPI,
    private_key: Union[DilithiumPrivateKey, any],
    chain_id: int = None,
) -> Union[VRS, bytes]:
    """
    Create a transaction signature using Dilithium (quantum-resistant) or legacy ECDSA.
    
    For QRDX transactions, returns the Dilithium signature as bytes.
    For legacy transactions, returns VRS tuple.
    """
    # Check if this is a QRDX transaction with Dilithium key
    if isinstance(private_key, DilithiumPrivateKey):
        # QRDX quantum-resistant signature
        # For QRDX transactions, chain_id is already part of the transaction fields,
        # so we don't append it again
        transaction_parts = rlp.decode(rlp.encode(unsigned_txn))
        message = rlp.encode(transaction_parts)
        signature = private_key.sign(message)
        return signature
    else:
        # Legacy ECDSA signature (for backward compatibility testing)
        try:
            from eth_keys import datatypes
            transaction_parts = rlp.decode(rlp.encode(unsigned_txn))

            if chain_id:
                transaction_parts_for_signature = transaction_parts + [
                    int_to_big_endian(chain_id),
                    b"",
                    b"",
                ]
            else:
                transaction_parts_for_signature = transaction_parts

            message = rlp.encode(transaction_parts_for_signature)
            signature = private_key.sign_msg(message)

            canonical_v, r, s = signature.vrs

            if chain_id:
                v = canonical_v + chain_id * 2 + EIP155_CHAIN_ID_OFFSET
            else:
                v = canonical_v + V_OFFSET

            return VRS((v, r, s))
        except ImportError:
            raise ValidationError("eth_keys not available for legacy signatures")


def validate_transaction_signature(transaction: SignedTransactionAPI) -> None:
    """
    Validate a transaction signature (Dilithium for QRDX, ECDSA for legacy).
    """
    message = transaction.get_message_for_signing()
    
    # Check if this is a QRDX transaction with Dilithium signature
    if hasattr(transaction, 'public_key') and hasattr(transaction, 'signature'):
        # QRDX quantum-resistant signature validation
        public_key_bytes = transaction.public_key
        signature_bytes = transaction.signature
        
        if not verify_dilithium_signature(message, signature_bytes, public_key_bytes):
            raise ValidationError("Invalid Dilithium signature")
    else:
        # Legacy ECDSA validation
        try:
            from eth_keys import keys
            from eth_keys.exceptions import BadSignature
            
            vrs = (transaction.y_parity, transaction.r, transaction.s)
            try:
                signature = keys.Signature(vrs=vrs)
                public_key = signature.recover_public_key_from_msg(message)
            except BadSignature as e:
                raise ValidationError(f"Bad Signature: {str(e)}")

            if not signature.verify_msg(message, public_key):
                raise ValidationError("Invalid Signature")
        except ImportError:
            raise ValidationError("Cannot validate legacy ECDSA signatures without eth_keys")


def extract_transaction_sender(transaction: SignedTransactionAPI) -> Address:
    """
    Extract the sender address from a transaction signature.
    
    For QRDX transactions, derives address from Dilithium public key.
    For legacy transactions, recovers from ECDSA signature.
    """
    # Check if this is a QRDX transaction with Dilithium public key
    if hasattr(transaction, 'public_key'):
        # QRDX: Derive address from public key using BLAKE3
        public_key_bytes = transaction.public_key
        return address_from_public_key(public_key_bytes)
    else:
        # Legacy ECDSA sender extraction
        try:
            from eth_keys import keys
            
            vrs = (transaction.y_parity, transaction.r, transaction.s)
            signature = keys.Signature(vrs=vrs)
            message = transaction.get_message_for_signing()
            public_key = signature.recover_public_key_from_msg(message)
            sender = public_key.to_canonical_address()
            return Address(sender)
        except ImportError:
            raise ValidationError("Cannot extract sender from legacy transactions without eth_keys")


class IntrinsicGasSchedule(NamedTuple):
    gas_tx: int
    gas_txcreate: int
    gas_txdatazero: int
    gas_txdatanonzero: int


def calculate_intrinsic_gas(
    gas_schedule: IntrinsicGasSchedule,
    transaction: Union[SignedTransactionAPI, UnsignedTransactionAPI],
) -> int:
    num_zero_bytes = transaction.data.count(b"\x00")
    num_non_zero_bytes = len(transaction.data) - num_zero_bytes
    if transaction.to == CREATE_CONTRACT_ADDRESS:
        create_cost = gas_schedule.gas_txcreate
    else:
        create_cost = 0
    return (
        gas_schedule.gas_tx
        + num_zero_bytes * gas_schedule.gas_txdatazero
        + num_non_zero_bytes * gas_schedule.gas_txdatanonzero
        # Note: The per-word create cost is not included in the intrinsic gas
        # calculation because the intrinsic cost is deducted from the transaction
        # before computation. So this cost is therefore subtracted when the computation
        # runs the appropriate opcode(s).
        + create_cost
    )
