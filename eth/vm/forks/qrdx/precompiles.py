"""
QRDX Precompiled Contracts

Quantum-resistant cryptography precompiles for smart contracts.
Each precompile follows the py-evm convention: a plain function that
takes a ComputationAPI instance, charges gas, sets output, and returns
the computation.

Address Assignments (Whitepaper §3.3):
- 0x09: Dilithium (ML-DSA-65) signature verification
- 0x0a: Kyber (ML-KEM-768) key encapsulation
- 0x0b: Kyber (ML-KEM-768) decapsulation
- 0x0c: BLAKE3-256 hashing

Retired exchange precompiles (0x0100–0x0104): reserved, and revert. They ran a separate,
simulated exchange — pools keyed by symbol strings, no tokens moved, no state root. The
exchange is reached with exchange transactions (docs/PERPS_API.md).

Oracle Precompiles (Whitepaper §3.3 / Step 4.5):
- 0x0200: getChainState — read attested external chain state
- 0x0201: verifyExternalProof — verify Merkle/SPV inclusion proof
- 0x0202: submitCrossChainTx — submit cross-chain oracle transaction

Key sizes (ML-KEM-768 / NIST FIPS 203):
  public_key    = 1,184 bytes
  secret_key    = 2,400 bytes
  ciphertext    = 1,088 bytes
  shared_secret = 32 bytes

Key sizes (ML-DSA-65 / NIST FIPS 204):
  public_key  = 1,952 bytes
  signature   = 3,309 bytes
"""

from eth.abc import ComputationAPI
from eth_typing import Address

from eth.crypto import (
    verify_dilithium_signature,
    kyber_encapsulate,
    kyber_decapsulate,
    blake3_hash_bytes,
)

# ── Precompile Addresses ──────────────────────────────────────────────

DILITHIUM_VERIFY_ADDRESS = Address(b'\x00' * 19 + b'\x09')
KYBER_ENCAPSULATE_ADDRESS = Address(b'\x00' * 19 + b'\x0a')
KYBER_DECAPSULATE_ADDRESS = Address(b'\x00' * 19 + b'\x0b')
BLAKE3_HASH_ADDRESS = Address(b'\x00' * 19 + b'\x0c')

# Oracle precompiles (Step 4.5 — 0x0200 range)
ORACLE_GET_CHAIN_STATE_ADDRESS = Address(b'\x00' * 18 + b'\x02\x00')
ORACLE_VERIFY_PROOF_ADDRESS = Address(b'\x00' * 18 + b'\x02\x01')
ORACLE_SUBMIT_CROSS_CHAIN_TX_ADDRESS = Address(b'\x00' * 18 + b'\x02\x02')

# ── Size Constants ────────────────────────────────────────────────────

# Dilithium / ML-DSA-65
DILITHIUM_MSG_HASH_SIZE = 32
DILITHIUM_PUBKEY_SIZE = 1_952
DILITHIUM_SIGNATURE_SIZE = 3_309
DILITHIUM_INPUT_SIZE = DILITHIUM_MSG_HASH_SIZE + DILITHIUM_PUBKEY_SIZE + DILITHIUM_SIGNATURE_SIZE  # 5,293

# Kyber / ML-KEM-768
KYBER_PUBKEY_SIZE = 1_184
KYBER_SECRET_KEY_SIZE = 2_400
KYBER_CIPHERTEXT_SIZE = 1_088
KYBER_SHARED_SECRET_SIZE = 32
KYBER_ENCAP_INPUT_SIZE = KYBER_PUBKEY_SIZE                                      # 1,184
KYBER_DECAP_INPUT_SIZE = KYBER_SECRET_KEY_SIZE + KYBER_CIPHERTEXT_SIZE          # 3,488

# ── Gas Constants ─────────────────────────────────────────────────────

GAS_DILITHIUM_VERIFY = 50_000
GAS_KYBER_ENCAPSULATE = 30_000
GAS_KYBER_DECAPSULATE = 30_000
GAS_BLAKE3_BASE = 60
GAS_BLAKE3_PER_WORD = 12

# Oracle precompile gas costs
GAS_ORACLE_GET_CHAIN_STATE = 100_000
GAS_ORACLE_VERIFY_PROOF = 200_000
GAS_ORACLE_SUBMIT_CROSS_CHAIN_TX = 500_000

# Retired exchange precompile addresses (0x0100 range): reserved, they revert
EXCHANGE_CREATE_POOL_ADDRESS = Address(b'\x00' * 18 + b'\x01\x00')
EXCHANGE_SWAP_ADDRESS = Address(b'\x00' * 18 + b'\x01\x01')
EXCHANGE_ADD_LIQUIDITY_ADDRESS = Address(b'\x00' * 18 + b'\x01\x02')
EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS = Address(b'\x00' * 18 + b'\x01\x03')
EXCHANGE_CANCEL_ORDER_ADDRESS = Address(b'\x00' * 18 + b'\x01\x04')

GAS_RETIRED_EXCHANGE_PRECOMPILE = 2_600     # a cold call's worth: reverting must not be free

# Oracle ABI sizes
ORACLE_CHAIN_ID_SIZE = 4             # 4 bytes for chain_id
ORACLE_BLOCK_HEIGHT_SIZE = 8         # 8 bytes for block height
ORACLE_HASH_SIZE = 32                # 32 bytes for block/state hash
ORACLE_TIMESTAMP_SIZE = 8            # 8 bytes for timestamp
# getChainState output: block_height(8) + block_hash(32) + state_root(32) + timestamp(8) = 80
ORACLE_CHAIN_STATE_OUTPUT_SIZE = 80


# ── Precompile Functions ──────────────────────────────────────────────
# Each function follows the py-evm pattern (see eth/precompiles/sha256.py):
#   1. Compute & consume gas
#   2. Validate input
#   3. Execute logic
#   4. Set computation.output
#   5. Return computation

def dilithium_verify(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x09: Dilithium (ML-DSA-65) signature verification.

    Input (5,293 bytes):
        message_hash  [0:32]       — 32-byte BLAKE3 hash of the message
        public_key    [32:1984]    — 1,952-byte ML-DSA-65 public key
        signature     [1984:5293]  — 3,309-byte ML-DSA-65 signature

    Output (1 byte):
        0x01 if the signature is valid, 0x00 otherwise.
    """
    computation.consume_gas(GAS_DILITHIUM_VERIFY, reason="Dilithium Verify Precompile")

    input_data = computation.msg.data

    if len(input_data) != DILITHIUM_INPUT_SIZE:
        computation.output = b'\x00'
        return computation

    message_hash = input_data[0:DILITHIUM_MSG_HASH_SIZE]
    public_key = input_data[DILITHIUM_MSG_HASH_SIZE:DILITHIUM_MSG_HASH_SIZE + DILITHIUM_PUBKEY_SIZE]
    signature = input_data[DILITHIUM_MSG_HASH_SIZE + DILITHIUM_PUBKEY_SIZE:DILITHIUM_INPUT_SIZE]

    try:
        is_valid = verify_dilithium_signature(message_hash, signature, public_key)
        computation.output = b'\x01' if is_valid else b'\x00'
    except Exception:
        computation.output = b'\x00'

    return computation


def kyber_encapsulate_precompile(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0a: Kyber (ML-KEM-768) key encapsulation.

    Input (1,184 bytes):
        public_key  [0:1184] — ML-KEM-768 public key

    Output (1,120 bytes):
        ciphertext     [0:1088]    — 1,088-byte ciphertext
        shared_secret  [1088:1120] — 32-byte shared secret
    """
    computation.consume_gas(GAS_KYBER_ENCAPSULATE, reason="Kyber Encapsulate Precompile")

    input_data = computation.msg.data

    if len(input_data) != KYBER_ENCAP_INPUT_SIZE:
        computation.output = b''
        return computation

    try:
        ciphertext, shared_secret = kyber_encapsulate(input_data)
        computation.output = ciphertext + shared_secret
    except Exception:
        computation.output = b''

    return computation


def kyber_decapsulate_precompile(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0b: Kyber (ML-KEM-768) decapsulation.

    Input (3,488 bytes):
        secret_key  [0:2400]     — 2,400-byte ML-KEM-768 secret key
        ciphertext  [2400:3488]  — 1,088-byte ciphertext

    Output (32 bytes):
        shared_secret — 32-byte decapsulated shared secret
    """
    computation.consume_gas(GAS_KYBER_DECAPSULATE, reason="Kyber Decapsulate Precompile")

    input_data = computation.msg.data

    if len(input_data) != KYBER_DECAP_INPUT_SIZE:
        computation.output = b''
        return computation

    secret_key = input_data[0:KYBER_SECRET_KEY_SIZE]
    ciphertext = input_data[KYBER_SECRET_KEY_SIZE:KYBER_DECAP_INPUT_SIZE]

    try:
        shared_secret = kyber_decapsulate(ciphertext, secret_key)
        computation.output = shared_secret
    except Exception:
        computation.output = b''

    return computation


def blake3_hash_precompile(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0c: BLAKE3-256 hashing.

    Input (variable):
        data — arbitrary bytes to hash

    Output (32 bytes):
        hash — BLAKE3-256 digest
    """
    data_size = len(computation.msg.data)
    word_count = (data_size + 31) // 32
    gas_fee = GAS_BLAKE3_BASE + GAS_BLAKE3_PER_WORD * word_count

    computation.consume_gas(gas_fee, reason="BLAKE3 Precompile")

    try:
        computation.output = blake3_hash_bytes(computation.msg.data)
    except Exception:
        computation.output = b''

    return computation


# ── Oracle Precompile Functions ───────────────────────────────────────
# Step 4.5: Oracle precompiles 0x0200–0x0202

# Oracle chain state store — populated by `oracle_set_chain_state()` which is
# called by the validator bridge integration layer when new attested cross-chain
# block heights are finalized via quorum (see `qrdx/bridge/adapters.py:
# BlockHeightTracker`).  In production, this module-level dict is the EVM's
# read-only view of the attested cross-chain state.
_oracle_chain_states: dict = {}


def oracle_set_chain_state(chain_id: int, block_height: int, block_hash: bytes,
                           state_root: bytes, timestamp: int) -> None:
    """
    Inject chain state for the oracle precompiles (used by validators / tests).

    Args:
        chain_id: 4-byte chain identifier
        block_height: 8-byte block height
        block_hash: 32-byte block hash
        state_root: 32-byte state root
        timestamp: 8-byte unix timestamp
    """
    _oracle_chain_states[chain_id] = {
        "block_height": block_height,
        "block_hash": block_hash[:32].ljust(32, b'\x00'),
        "state_root": state_root[:32].ljust(32, b'\x00'),
        "timestamp": timestamp,
    }


def get_chain_state_precompile(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0200: getChainState — read attested external chain state.

    Input (4 bytes):
        chain_id  [0:4]  — 4-byte big-endian external chain identifier

    Output (80 bytes):
        block_height  [0:8]    — 8-byte big-endian latest attested height
        block_hash    [8:40]   — 32-byte block hash
        state_root    [40:72]  — 32-byte state root
        timestamp     [72:80]  — 8-byte big-endian unix timestamp

    Returns all zeros if no state is available for the requested chain.
    """
    computation.consume_gas(GAS_ORACLE_GET_CHAIN_STATE, reason="Oracle getChainState")

    input_data = computation.msg.data

    if len(input_data) < ORACLE_CHAIN_ID_SIZE:
        computation.output = b'\x00' * ORACLE_CHAIN_STATE_OUTPUT_SIZE
        return computation

    chain_id = int.from_bytes(input_data[:ORACLE_CHAIN_ID_SIZE], 'big')

    state = _oracle_chain_states.get(chain_id)
    if state is None:
        computation.output = b'\x00' * ORACLE_CHAIN_STATE_OUTPUT_SIZE
        return computation

    try:
        output = (
            state["block_height"].to_bytes(ORACLE_BLOCK_HEIGHT_SIZE, 'big') +
            state["block_hash"] +
            state["state_root"] +
            state["timestamp"].to_bytes(ORACLE_TIMESTAMP_SIZE, 'big')
        )
        computation.output = output
    except Exception:
        computation.output = b'\x00' * ORACLE_CHAIN_STATE_OUTPUT_SIZE

    return computation


def verify_external_proof_precompile(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0201: verifyExternalProof — verify Merkle/SPV inclusion proof.

    Input (variable, minimum 36 bytes):
        chain_id    [0:4]    — 4-byte chain identifier
        proof_data  [4:]     — chain-specific proof (Merkle-Patricia for ETH,
                               SPV for BTC, slot-hash for SOL)

    Output (1 byte):
        0x01 if the proof verifies against the chain's attested state, 0x00 otherwise.

    Fails closed: no chain adapter verifies proofs yet, so every proof is reported
    invalid (0x00). It used to report "valid" for any non-zero 32 bytes on a known
    chain id — a contract that trusted it would have accepted forged proofs.
    """
    computation.consume_gas(GAS_ORACLE_VERIFY_PROOF, reason="Oracle verifyExternalProof")

    input_data = computation.msg.data

    # Minimum: 4 bytes chain_id + 32 bytes proof_data
    if len(input_data) < ORACLE_CHAIN_ID_SIZE + ORACLE_HASH_SIZE:
        computation.output = b'\x00'
        return computation

    chain_id = int.from_bytes(input_data[:ORACLE_CHAIN_ID_SIZE], 'big')

    # Validate chain_id is known (0=QRDX, 1=ETH, 2=BTC, 3=SOL, 4=COSMOS)
    if chain_id > 4:
        computation.output = b'\x00'
        return computation

    proof_data = input_data[ORACLE_CHAIN_ID_SIZE:]

    # Must have at least 32 bytes of proof data
    if len(proof_data) < ORACLE_HASH_SIZE:
        computation.output = b'\x00'
        return computation

    # No verifier exists for any chain yet: a structurally plausible proof is not a proven
    # one. Report invalid until a chain adapter checks it against attested state.
    computation.output = b'\x00'
    return computation


def submit_cross_chain_tx_precompile(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0202: submitCrossChainTx — submit cross-chain oracle tx.

    Input (variable, minimum 36 bytes):
        chain_id   [0:4]    — 4-byte destination chain identifier
        tx_data    [4:]     — fully-signed external chain transaction

    Output (32 bytes):
        tx_hash — SHA-256 hash of (chain_id || tx_data), serving as the
                  oracle transaction identifier on QRDX

    Returns all zeros on invalid input.
    """
    computation.consume_gas(GAS_ORACLE_SUBMIT_CROSS_CHAIN_TX, reason="Oracle submitCrossChainTx")

    input_data = computation.msg.data

    if len(input_data) < ORACLE_CHAIN_ID_SIZE + 1:
        computation.output = b'\x00' * ORACLE_HASH_SIZE
        return computation

    chain_id = int.from_bytes(input_data[:ORACLE_CHAIN_ID_SIZE], 'big')

    if chain_id > 4 or chain_id == 0:
        # Cannot submit to QRDX itself (chain_id 0) or unknown chain
        computation.output = b'\x00' * ORACLE_HASH_SIZE
        return computation

    tx_data = input_data[ORACLE_CHAIN_ID_SIZE:]
    if not tx_data:
        computation.output = b'\x00' * ORACLE_HASH_SIZE
        return computation

    import hashlib
    tx_hash = hashlib.sha256(input_data).digest()
    computation.output = tx_hash
    return computation


# ── Retired exchange precompiles (0x0100–0x0104) ──────────────────────

RETIRED_EXCHANGE_REASON = ("QRDX exchange precompiles are retired: trade with exchange "
                           "transactions (spot, perps, tokens)")


def _error_string(reason: str) -> bytes:
    raw = reason.encode("utf-8")
    return (bytes.fromhex("08c379a0") + (32).to_bytes(32, "big") + len(raw).to_bytes(32, "big")
            + raw + b"\x00" * ((-len(raw)) % 32))


def retired_exchange_precompile(computation: ComputationAPI) -> ComputationAPI:
    """0x0100–0x0104 used to run a separate, simulated exchange (pools keyed by symbol strings,
    no tokens moved, nothing in any state root). The addresses stay reserved and REVERT with
    ``Error(string)``, so a contract written against them fails loudly instead of reading an
    empty answer as success."""
    from eth.exceptions import Revert
    computation.consume_gas(GAS_RETIRED_EXCHANGE_PRECOMPILE, reason="retired exchange precompile")
    computation.output = _error_string(RETIRED_EXCHANGE_REASON)
    raise Revert(RETIRED_EXCHANGE_REASON)


# ── Precompile Registry ───────────────────────────────────────────────
# Maps Address → Callable[[ComputationAPI], ComputationAPI]
# This is the format required by py-evm (see eth/vm/computation.py line 386).

QRDX_PRECOMPILES = {
    DILITHIUM_VERIFY_ADDRESS: dilithium_verify,
    KYBER_ENCAPSULATE_ADDRESS: kyber_encapsulate_precompile,
    KYBER_DECAPSULATE_ADDRESS: kyber_decapsulate_precompile,
    BLAKE3_HASH_ADDRESS: blake3_hash_precompile,
    # Retired exchange precompiles (0x0100 range): reserved, revert.
    EXCHANGE_CREATE_POOL_ADDRESS: retired_exchange_precompile,
    EXCHANGE_SWAP_ADDRESS: retired_exchange_precompile,
    EXCHANGE_ADD_LIQUIDITY_ADDRESS: retired_exchange_precompile,
    EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS: retired_exchange_precompile,
    EXCHANGE_CANCEL_ORDER_ADDRESS: retired_exchange_precompile,
    # Oracle precompiles (0x0200 range — Step 4.5)
    ORACLE_GET_CHAIN_STATE_ADDRESS: get_chain_state_precompile,
    ORACLE_VERIFY_PROOF_ADDRESS: verify_external_proof_precompile,
    ORACLE_SUBMIT_CROSS_CHAIN_TX_ADDRESS: submit_cross_chain_tx_precompile,
}
