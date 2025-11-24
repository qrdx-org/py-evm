"""
CRYSTALS-Kyber Implementation for QRDX Chain

Provides key encapsulation mechanism (KEM) using the NIST-standardized
CRYSTALS-Kyber algorithm (FIPS 203, Level 3).

Note: liboqs supports both "Kyber768" and "ML-KEM-768" (final NIST name).
ML-KEM-768 corresponds to Kyber768/Level 3.

Key sizes (ML-KEM-768):
- Private key: 2,400 bytes
- Public key: 1,184 bytes
- Ciphertext: 1,088 bytes
- Shared secret: 32 bytes

Security: NIST Level 3 (equivalent to AES-192 against quantum attacks)

Use cases:
- Encrypted transaction pools
- Secure validator communication
- Bridge security
"""

from typing import Tuple
import oqs
from eth_utils import ValidationError


# Kyber security level 3 (ML-KEM-768 is the NIST final name for Kyber768)
KYBER_VARIANT = "ML-KEM-768"

# Key and ciphertext sizes for ML-KEM-768 (Kyber768)
KYBER_PUBLIC_KEY_SIZE = 1184
KYBER_SECRET_KEY_SIZE = 2400
KYBER_CIPHERTEXT_SIZE = 1088
KYBER_SHARED_SECRET_SIZE = 32


class KyberPublicKey:
    """
    Represents a CRYSTALS-Kyber public key for key encapsulation.
    """
    
    def __init__(self, public_key_bytes: bytes) -> None:
        """
        Initialize a Kyber public key from bytes.
        
        Args:
            public_key_bytes: The public key as bytes (1,184 bytes for Kyber768)
        
        Raises:
            ValidationError: If public key size is invalid
        """
        if len(public_key_bytes) != KYBER_PUBLIC_KEY_SIZE:
            raise ValidationError(
                f"Invalid Kyber public key size. "
                f"Expected {KYBER_PUBLIC_KEY_SIZE} bytes, "
                f"got {len(public_key_bytes)} bytes"
            )
        self._public_key_bytes = public_key_bytes
    
    def to_bytes(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes
    
    def to_hex(self) -> str:
        """Return the public key as a hex string."""
        return self._public_key_bytes.hex()
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KyberPublicKey):
            return False
        return self._public_key_bytes == other._public_key_bytes
    
    def __repr__(self) -> str:
        return f"KyberPublicKey({self.to_hex()[:16]}...)"


class KyberPrivateKey:
    """
    Represents a CRYSTALS-Kyber private key for decapsulation.
    """
    
    def __init__(self, private_key_bytes: bytes) -> None:
        """
        Initialize a Kyber private key from bytes.
        
        Args:
            private_key_bytes: The private key as bytes (2,400 bytes for Kyber768)
        
        Raises:
            ValidationError: If private key size is invalid
        """
        if len(private_key_bytes) != KYBER_SECRET_KEY_SIZE:
            raise ValidationError(
                f"Invalid Kyber private key size. "
                f"Expected {KYBER_SECRET_KEY_SIZE} bytes, "
                f"got {len(private_key_bytes)} bytes"
            )
        self._private_key_bytes = private_key_bytes
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate a ciphertext to recover the shared secret.
        
        Args:
            ciphertext: The encapsulated ciphertext (1,088 bytes)
        
        Returns:
            The shared secret (32 bytes)
        
        Raises:
            ValidationError: If ciphertext size is invalid
            Exception: If decapsulation fails
        """
        if len(ciphertext) != KYBER_CIPHERTEXT_SIZE:
            raise ValidationError(
                f"Invalid Kyber ciphertext size. "
                f"Expected {KYBER_CIPHERTEXT_SIZE} bytes, "
                f"got {len(ciphertext)} bytes"
            )
        
        with oqs.KeyEncapsulation(KYBER_VARIANT, secret_key=self._private_key_bytes) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret
    
    def to_bytes(self) -> bytes:
        """Return the private key as bytes. WARNING: Keep this secret!"""
        return self._private_key_bytes
    
    def __repr__(self) -> str:
        return "KyberPrivateKey(<secret>)"


def generate_kyber_keypair() -> Tuple[KyberPrivateKey, KyberPublicKey]:
    """
    Generate a new Kyber key pair for key encapsulation.
    
    Returns:
        A tuple of (private_key, public_key)
    
    Example:
        >>> private_key, public_key = generate_kyber_keypair()
        >>> ciphertext, shared_secret1 = kyber_encapsulate(public_key.to_bytes())
        >>> shared_secret2 = private_key.decapsulate(ciphertext)
        >>> assert shared_secret1 == shared_secret2
    """
    with oqs.KeyEncapsulation(KYBER_VARIANT) as kem:
        public_key_bytes = kem.generate_keypair()
        secret_key_bytes = kem.export_secret_key()
        
        public_key = KyberPublicKey(public_key_bytes)
        private_key = KyberPrivateKey(secret_key_bytes)
        
        return private_key, public_key


def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using a Kyber public key.
    
    Args:
        public_key: The Kyber public key as bytes (1,184 bytes)
    
    Returns:
        A tuple of (ciphertext, shared_secret)
        - ciphertext: The encapsulated ciphertext (1,088 bytes)
        - shared_secret: The shared secret (32 bytes)
    
    Raises:
        ValidationError: If public key size is invalid
    """
    if len(public_key) != KYBER_PUBLIC_KEY_SIZE:
        raise ValidationError(
            f"Invalid Kyber public key size. "
            f"Expected {KYBER_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(public_key)} bytes"
        )
    
    with oqs.KeyEncapsulation(KYBER_VARIANT) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret


def kyber_decapsulate(ciphertext: bytes, private_key: bytes) -> bytes:
    """
    Decapsulate a ciphertext to recover the shared secret (convenience function).
    
    Args:
        ciphertext: The encapsulated ciphertext (1,088 bytes)
        private_key: The Kyber private key as bytes (2,400 bytes)
    
    Returns:
        The shared secret (32 bytes)
    
    Raises:
        ValidationError: If sizes are invalid
        Exception: If decapsulation fails
    """
    priv_key = KyberPrivateKey(private_key)
    return priv_key.decapsulate(ciphertext)
