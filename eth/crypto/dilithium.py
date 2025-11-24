"""
CRYSTALS-Dilithium Implementation for QRDX Chain

Provides digital signature functionality using the NIST-standardized
CRYSTALS-Dilithium algorithm (FIPS 204, Level 3).

Note: liboqs uses the final NIST name "ML-DSA" (Module-Lattice-Based Digital Signature Algorithm)
for Dilithium. ML-DSA-65 corresponds to Dilithium3/Level 3.

Key sizes:
- Private key: 4,032 bytes
- Public key: 1,952 bytes  
- Signature: 3,309 bytes

Security: NIST Level 3 (equivalent to AES-192 against quantum attacks)
"""

from typing import Tuple, Optional
import oqs
from eth_typing import Address
from eth_utils import ValidationError


# Dilithium security level 3 (ML-DSA-65 is the NIST final name for Dilithium3)
DILITHIUM_VARIANT = "ML-DSA-65"

# Key and signature sizes for ML-DSA-65 (Dilithium3)
DILITHIUM_PUBLIC_KEY_SIZE = 1952
DILITHIUM_SECRET_KEY_SIZE = 4032
DILITHIUM_SIGNATURE_SIZE = 3309


class DilithiumPublicKey:
    """
    Represents a CRYSTALS-Dilithium public key for signature verification.
    """
    
    def __init__(self, public_key_bytes: bytes) -> None:
        """
        Initialize a Dilithium public key from bytes.
        
        Args:
            public_key_bytes: The public key as bytes (1,952 bytes for Dilithium3)
        
        Raises:
            ValidationError: If public key size is invalid
        """
        if len(public_key_bytes) != DILITHIUM_PUBLIC_KEY_SIZE:
            raise ValidationError(
                f"Invalid Dilithium public key size. "
                f"Expected {DILITHIUM_PUBLIC_KEY_SIZE} bytes, "
                f"got {len(public_key_bytes)} bytes"
            )
        self._public_key_bytes = public_key_bytes
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a Dilithium signature on a message.
        
        Args:
            message: The message that was signed
            signature: The Dilithium signature (3,293 bytes)
        
        Returns:
            True if signature is valid, False otherwise
        """
        if len(signature) != DILITHIUM_SIGNATURE_SIZE:
            return False
        
        try:
            with oqs.Signature(DILITHIUM_VARIANT) as verifier:
                # liboqs verify function raises exception on invalid signature
                is_valid = verifier.verify(message, signature, self._public_key_bytes)
                return is_valid
        except Exception:
            return False
    
    def to_bytes(self) -> bytes:
        """Return the public key as bytes."""
        return self._public_key_bytes
    
    def to_hex(self) -> str:
        """Return the public key as a hex string."""
        return self._public_key_bytes.hex()
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DilithiumPublicKey):
            return False
        return self._public_key_bytes == other._public_key_bytes
    
    def __repr__(self) -> str:
        return f"DilithiumPublicKey({self.to_hex()[:16]}...)"


class DilithiumPrivateKey:
    """
    Represents a CRYSTALS-Dilithium private key for signing.
    """
    
    def __init__(self, private_key_bytes: bytes, public_key_bytes: Optional[bytes] = None) -> None:
        """
        Initialize a Dilithium private key from bytes.
        
        Args:
            private_key_bytes: The private key as bytes (4,032 bytes for ML-DSA-65)
            public_key_bytes: Optional public key bytes (if not provided, will be derived)
        
        Raises:
            ValidationError: If private key size is invalid
        """
        if len(private_key_bytes) != DILITHIUM_SECRET_KEY_SIZE:
            raise ValidationError(
                f"Invalid Dilithium private key size. "
                f"Expected {DILITHIUM_SECRET_KEY_SIZE} bytes, "
                f"got {len(private_key_bytes)} bytes"
            )
        
        self._private_key_bytes = private_key_bytes
        
        # If public key not provided, derive it from private key
        if public_key_bytes is None:
            # liboqs stores public key within the secret key structure
            # For Dilithium3, the public key is embedded in the secret key
            # We need to extract it or regenerate
            with oqs.Signature(DILITHIUM_VARIANT) as signer:
                # This is a workaround - in practice, public key should be passed
                # or stored separately. liboqs doesn't provide direct extraction.
                # For now, we'll require it to be passed or set it to None
                self._public_key_bytes = None
        else:
            if len(public_key_bytes) != DILITHIUM_PUBLIC_KEY_SIZE:
                raise ValidationError(
                    f"Invalid Dilithium public key size. "
                    f"Expected {DILITHIUM_PUBLIC_KEY_SIZE} bytes"
                )
            self._public_key_bytes = public_key_bytes
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using this private key.
        
        Args:
            message: The message to sign
        
        Returns:
            The Dilithium signature (3,293 bytes)
        
        Raises:
            Exception: If signing fails
        """
        with oqs.Signature(DILITHIUM_VARIANT, secret_key=self._private_key_bytes) as signer:
            signature = signer.sign(message)
            return signature
    
    def public_key(self) -> DilithiumPublicKey:
        """
        Get the corresponding public key.
        
        Returns:
            The DilithiumPublicKey instance
        
        Raises:
            ValidationError: If public key was not provided during initialization
        """
        if self._public_key_bytes is None:
            raise ValidationError(
                "Public key not available. "
                "Please provide public_key_bytes during initialization."
            )
        return DilithiumPublicKey(self._public_key_bytes)
    
    def to_bytes(self) -> bytes:
        """Return the private key as bytes. WARNING: Keep this secret!"""
        return self._private_key_bytes
    
    def __repr__(self) -> str:
        return "DilithiumPrivateKey(<secret>)"


def generate_dilithium_keypair() -> Tuple[DilithiumPrivateKey, DilithiumPublicKey]:
    """
    Generate a new Dilithium key pair for signing.
    
    Returns:
        A tuple of (private_key, public_key)
    
    Example:
        >>> private_key, public_key = generate_dilithium_keypair()
        >>> message = b"Hello, quantum-resistant world!"
        >>> signature = private_key.sign(message)
        >>> assert public_key.verify(message, signature)
    """
    with oqs.Signature(DILITHIUM_VARIANT) as signer:
        public_key_bytes = signer.generate_keypair()
        secret_key_bytes = signer.export_secret_key()
        
        public_key = DilithiumPublicKey(public_key_bytes)
        private_key = DilithiumPrivateKey(secret_key_bytes, public_key_bytes)
        
        return private_key, public_key


def verify_dilithium_signature(
    message: bytes,
    signature: bytes,
    public_key: bytes
) -> bool:
    """
    Verify a Dilithium signature (convenience function).
    
    Args:
        message: The message that was signed
        signature: The Dilithium signature
        public_key: The public key as bytes
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        pub_key = DilithiumPublicKey(public_key)
        return pub_key.verify(message, signature)
    except Exception:
        return False
