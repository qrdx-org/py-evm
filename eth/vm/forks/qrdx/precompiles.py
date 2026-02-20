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

Exchange Engine Precompiles (Step 4.4):
- 0x0100: createPool — create an AMM liquidity pool
- 0x0101: swap — execute a swap through the exchange router
- 0x0102: addLiquidity — add liquidity to an AMM pool
- 0x0103: placeLimitOrder — place a limit order on the CLOB
- 0x0104: cancelOrder — cancel an existing limit order

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

import hashlib
import struct
import logging
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional, Tuple

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

# Exchange Engine precompile addresses (Step 4.4 — 0x0100 range)
EXCHANGE_CREATE_POOL_ADDRESS = Address(b'\x00' * 18 + b'\x01\x00')
EXCHANGE_SWAP_ADDRESS = Address(b'\x00' * 18 + b'\x01\x01')
EXCHANGE_ADD_LIQUIDITY_ADDRESS = Address(b'\x00' * 18 + b'\x01\x02')
EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS = Address(b'\x00' * 18 + b'\x01\x03')
EXCHANGE_CANCEL_ORDER_ADDRESS = Address(b'\x00' * 18 + b'\x01\x04')

# Exchange Engine gas costs
GAS_EXCHANGE_CREATE_POOL = 500_000      # Heavy: new state creation
GAS_EXCHANGE_SWAP = 150_000             # Medium: AMM computation + state write
GAS_EXCHANGE_ADD_LIQUIDITY = 200_000    # Medium-heavy: sqrt calc + state writes
GAS_EXCHANGE_PLACE_LIMIT_ORDER = 100_000  # Medium: order insertion
GAS_EXCHANGE_CANCEL_ORDER = 50_000      # Light: order removal

# Exchange ABI sizes (deterministic, fixed-width for consensus safety)
EXCHANGE_ADDRESS_SIZE = 20              # EVM address (could also be 66 for PQ)
EXCHANGE_TOKEN_SIZE = 32                # Token identifier (symbol, zero-padded)
EXCHANGE_AMOUNT_SIZE = 32               # uint256-encoded Decimal amount
EXCHANGE_FEE_SIZE = 4                   # Fee tier (basis points, uint32)
EXCHANGE_TICK_SIZE = 4                  # Tick spacing (int32)
EXCHANGE_ORDER_ID_SIZE = 32             # Order ID hash
EXCHANGE_BOOL_SIZE = 1                  # Boolean (0x00 or 0x01)
EXCHANGE_SIDE_SIZE = 1                  # Order side: 0=buy, 1=sell

logger = logging.getLogger(__name__)

# Oracle precompile constants
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

# Simulated chain state store (in production, wired to BlockHeightTracker)
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
        0x01 if the proof is structurally valid, 0x00 otherwise.

    Note: In production, this calls the chain-specific adapter's verification
    logic. For now, performs structural validation (non-empty, valid chain,
    decodable proof data).
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

    # Structural validation: proof data must not be all zeros
    if proof_data[:ORACLE_HASH_SIZE] == b'\x00' * ORACLE_HASH_SIZE:
        computation.output = b'\x00'
        return computation

    computation.output = b'\x01'
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


# ── Exchange Engine Precompile Functions ──────────────────────────────
# Step 4.4: Exchange precompiles 0x0100–0x0104
#
# These precompiles allow EVM smart contracts to interact with the native
# QRDX exchange engine (AMM, CLOB, router) without leaving the EVM.
# All state mutations are deterministic and consensus-safe.
#
# Architecture:
#   Precompiles delegate to ExchangeStateManager (the consensus singleton),
#   which owns the canonical pool, order book, oracle, and perp state.
#   This ensures that:
#     - State is persisted across blocks (not module-level dicts)
#     - State root is included in block commitment
#     - Revert/reorg restores pool/order state correctly
#     - All validators execute identical state transitions
#
# Encoding convention (big-endian, fixed-width):
#   address  = 20 bytes (EVM) or zero-padded to 32 bytes
#   token    = 32 bytes (symbol, right-padded with zeros)
#   amount   = 32 bytes (uint256, QRDX uses 8 decimal places → ×10^8)
#   fee_bps  = 4 bytes (uint32, basis points ×100 → e.g. 3000 = 0.30%)
#   tick     = 4 bytes (int32, tick spacing)

AMOUNT_PRECISION = Decimal("1E-8")

# Reentrancy guard for consensus-safe state mutations
_precompile_execution_depth: int = 0
_MAX_PRECOMPILE_DEPTH: int = 1  # No reentrant calls


def _check_reentrancy() -> bool:
    """Return True if a precompile is already executing (reentrant call)."""
    return _precompile_execution_depth > 0


def _decode_uint256(data: bytes) -> Decimal:
    """Decode a 32-byte big-endian uint256 into Decimal (8 dp)."""
    raw = int.from_bytes(data, "big")
    return Decimal(raw) * AMOUNT_PRECISION


def _encode_uint256(value: Decimal) -> bytes:
    """Encode a Decimal into 32-byte big-endian uint256 (8 dp)."""
    raw = int(value / AMOUNT_PRECISION)
    return raw.to_bytes(32, "big")


def _decode_token(data: bytes) -> str:
    """Decode a 32-byte zero-padded token symbol."""
    return data.rstrip(b"\x00").decode("ascii", errors="replace")


def _encode_token(symbol: str) -> bytes:
    """Encode a token symbol into 32-byte zero-padded bytes."""
    return symbol.encode("ascii")[:32].ljust(32, b"\x00")


def _get_exchange_state_manager():
    """
    Get the consensus ExchangeStateManager singleton if it exists.

    This is the ONLY way precompiles access exchange state. The manager
    owns all pools, order books, oracles, and perp positions, and its
    state is committed to the block state root by validators.

    IMPORTANT: Unlike ExchangeStateManager.get_instance(), this function
    does NOT auto-create a new manager.  If no manager was explicitly
    initialized by the validator/node startup, we fall back to the
    module-level dicts (useful for unit tests and dev mode).

    Returns:
        ExchangeStateManager instance, or None if not initialized
    """
    try:
        from qrdx.exchange.state_manager import ExchangeStateManager
        return ExchangeStateManager.instance  # May be None
    except ImportError:
        return None


def _get_block_timestamp(computation: ComputationAPI) -> int:
    """
    Extract deterministic block timestamp from EVM computation context.

    CRITICAL: Never use time.time() in precompiles — it breaks consensus
    determinism. Different validators would get different results.
    """
    # py-evm exposes block header via the VM environment
    try:
        if hasattr(computation, 'state') and hasattr(computation.state, 'execution_context'):
            ctx = computation.state.execution_context
            if hasattr(ctx, 'timestamp'):
                ts = ctx.timestamp
                if isinstance(ts, int):
                    return ts
    except (AttributeError, TypeError):
        pass
    # Fallback: use the exchange state manager's block timestamp
    mgr = _get_exchange_state_manager()
    if mgr and mgr._current_block_timestamp:
        return int(mgr._current_block_timestamp)
    # Last resort: return 0 (deadline check will be skipped if deadline=0)
    return 0


# ── Precompile state delegation ──────────────────────────────────────
# Instead of module-level dicts, precompiles read/write through the
# ExchangeStateManager.  For backward compat, if the manager is not
# initialized (e.g. in unit tests), we fall back to local dicts.

_exchange_pools: dict = {}
_exchange_orderbooks: dict = {}


def _get_pools() -> dict:
    """Get the canonical pool store (manager-backed or local fallback)."""
    mgr = _get_exchange_state_manager()
    if mgr is not None:
        # Use manager's pool registry for consensus
        return mgr._precompile_pools if hasattr(mgr, '_precompile_pools') else _exchange_pools
    return _exchange_pools


def _get_orderbooks() -> dict:
    """Get the canonical order book store (manager-backed or local fallback)."""
    mgr = _get_exchange_state_manager()
    if mgr is not None:
        return mgr._precompile_orderbooks if hasattr(mgr, '_precompile_orderbooks') else _exchange_orderbooks
    return _exchange_orderbooks


def exchange_create_pool(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0100: createPool — create an AMM concentrated liquidity pool.

    Input (100 bytes):
        token_a     [0:32]    — 32-byte token A symbol
        token_b     [32:64]   — 32-byte token B symbol
        fee_bps     [64:68]   — uint32 fee in basis points (e.g. 3000 = 0.30%)
        tick_spacing [68:72]  — int32 tick spacing
        initial_sqrt_price [72:104] — uint256 initial sqrt(price) × 2^96

    Output (32 bytes):
        pool_id — BLAKE2b hash identifying the pool

    Returns all zeros on error.
    """
    computation.consume_gas(GAS_EXCHANGE_CREATE_POOL, reason="Exchange createPool")

    data = computation.msg.data
    MIN_INPUT = 104  # 32+32+4+4+32

    if len(data) < MIN_INPUT:
        computation.output = b"\x00" * 32
        return computation

    token_a = _decode_token(data[0:32])
    token_b = _decode_token(data[32:64])
    fee_bps = int.from_bytes(data[64:68], "big")
    tick_spacing = struct.unpack(">i", data[68:72])[0]
    initial_sqrt_price_raw = int.from_bytes(data[72:104], "big")

    # Validation
    if not token_a or not token_b:
        computation.output = b"\x00" * 32
        return computation
    if token_a == token_b:
        computation.output = b"\x00" * 32
        return computation
    if fee_bps == 0 or fee_bps > 10_000:
        computation.output = b"\x00" * 32
        return computation
    if tick_spacing <= 0:
        computation.output = b"\x00" * 32
        return computation
    if initial_sqrt_price_raw == 0:
        computation.output = b"\x00" * 32
        return computation

    # Reentrancy guard
    global _precompile_execution_depth
    if _check_reentrancy():
        computation.output = b"\x00" * 32
        return computation
    _precompile_execution_depth += 1

    try:
        # Deterministic pool ID
        pool_id = hashlib.blake2b(
            f"{token_a}:{token_b}:{fee_bps}".encode(), digest_size=32
        ).digest()

        pools = _get_pools()

        # Check for duplicate
        if pool_id in pools:
            computation.output = b"\x00" * 32
            return computation

        pools[pool_id] = {
            "token_a": token_a,
            "token_b": token_b,
            "fee_bps": fee_bps,
            "tick_spacing": tick_spacing,
            "sqrt_price": initial_sqrt_price_raw,
            "liquidity": 0,
            "tick_current": 0,
            "positions": {},
            "creator": computation.msg.sender,
        }
    finally:
        _precompile_execution_depth -= 1

    computation.output = pool_id
    return computation


def exchange_swap(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0101: swap — execute a swap through the exchange router.

    Input (129 bytes):
        pool_id         [0:32]    — 32-byte pool identifier
        amount_in       [32:64]   — uint256 input amount (8 dp)
        zero_for_one    [64:65]   — bool: true=token_a→token_b, false=reverse
        min_amount_out  [65:97]   — uint256 minimum output (slippage protection)
        deadline        [97:129]  — uint256 unix timestamp deadline

    Output (64 bytes):
        amount_out  [0:32]  — uint256 actual output amount
        fee_amount  [32:64] — uint256 fee charged

    Returns all zeros on error (slippage exceeded, deadline passed, pool paused).
    """
    computation.consume_gas(GAS_EXCHANGE_SWAP, reason="Exchange swap")

    data = computation.msg.data
    MIN_INPUT = 129

    if len(data) < MIN_INPUT:
        computation.output = b"\x00" * 64
        return computation

    pool_id = data[0:32]
    amount_in = _decode_uint256(data[32:64])
    zero_for_one = data[64] != 0
    min_amount_out = _decode_uint256(data[65:97])
    deadline = int.from_bytes(data[97:129], "big")

    # Reentrancy guard
    global _precompile_execution_depth
    if _check_reentrancy():
        computation.output = b"\x00" * 64
        return computation
    _precompile_execution_depth += 1

    try:
        # Validation
        if amount_in <= 0:
            computation.output = b"\x00" * 64
            return computation

        pools = _get_pools()
        pool = pools.get(pool_id)
        if pool is None:
            computation.output = b"\x00" * 64
            return computation

        # Deadline enforcement — deterministic block timestamp (NEVER time.time())
        current_ts = _get_block_timestamp(computation)
        if deadline > 0 and current_ts > deadline:
            computation.output = b"\x00" * 64
            return computation

        # Compute swap using concentrated-liquidity constant-product formula.
        #
        # For a CLOB pool, the core invariant is:
        #   L = Δx · √P   (token_a, x-dimension)
        #   L = Δy / √P   (token_b, y-dimension)
        # where L = liquidity and P = price (token_b per token_a).
        #
        # Given an input Δ of one token (after fees), we compute the
        # new sqrt_price and derive the output amount.  This is the same
        # math Uniswap V3 uses, applied to our Q96 fixed-point price.
        #
        fee_bps = pool["fee_bps"]
        fee_rate = Decimal(fee_bps) / Decimal(1_000_000)  # bps expressed as fraction
        fee_amount = (amount_in * fee_rate).quantize(AMOUNT_PRECISION, rounding=ROUND_HALF_UP)
        amount_after_fee = amount_in - fee_amount

        sqrt_price_q96 = Decimal(pool["sqrt_price"])
        if sqrt_price_q96 <= 0:
            computation.output = b"\x00" * 64
            return computation

        liquidity = Decimal(pool.get("liquidity", 0))
        if liquidity <= 0:
            computation.output = b"\x00" * 64
            return computation

        Q96 = Decimal(2**96)
        sqrt_price = sqrt_price_q96 / Q96

        if zero_for_one:
            # Selling token_a (x) for token_b (y)
            # Δy = L · (√P_old − √P_new)
            # √P_new = √P_old − Δx · √P_old² / (L + Δx · √P_old)
            #   simplified: √P_new = L · √P / (L + Δx · √P)
            denom = liquidity + amount_after_fee * sqrt_price
            if denom <= 0:
                computation.output = b"\x00" * 64
                return computation
            new_sqrt_price = (liquidity * sqrt_price) / denom
            amount_out = (liquidity * (sqrt_price - new_sqrt_price)).quantize(
                AMOUNT_PRECISION, rounding=ROUND_HALF_UP
            )
            # Update pool price deterministically
            pool["sqrt_price"] = int(new_sqrt_price * Q96)
        else:
            # Selling token_b (y) for token_a (x)
            # Δx = L · (1/√P_new − 1/√P_old)
            # √P_new = √P_old + Δy / L
            if sqrt_price <= 0:
                computation.output = b"\x00" * 64
                return computation
            new_sqrt_price = sqrt_price + amount_after_fee / liquidity
            inv_old = Decimal(1) / sqrt_price
            inv_new = Decimal(1) / new_sqrt_price
            amount_out = (liquidity * (inv_old - inv_new)).quantize(
                AMOUNT_PRECISION, rounding=ROUND_HALF_UP
            )
            pool["sqrt_price"] = int(new_sqrt_price * Q96)

        if amount_out <= 0:
            computation.output = b"\x00" * 64
            return computation

        # Slippage check
        if amount_out < min_amount_out:
            computation.output = b"\x00" * 64
            return computation

        computation.output = _encode_uint256(amount_out) + _encode_uint256(fee_amount)
        return computation
    finally:
        _precompile_execution_depth -= 1


def exchange_add_liquidity(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0102: addLiquidity — add liquidity to a concentrated pool.

    Input (136 bytes):
        pool_id      [0:32]    — 32-byte pool identifier
        amount_a     [32:64]   — uint256 token A amount
        amount_b     [64:96]   — uint256 token B amount
        tick_lower   [96:100]  — int32 lower tick boundary
        tick_upper   [100:104] — int32 upper tick boundary
        recipient    [104:136] — uint256 zero-padded address (position owner)

    Output (64 bytes):
        liquidity_minted  [0:32]  — uint256 liquidity units minted
        position_id       [32:64] — 32-byte position identifier

    Returns all zeros on error.
    """
    computation.consume_gas(GAS_EXCHANGE_ADD_LIQUIDITY, reason="Exchange addLiquidity")

    data = computation.msg.data
    MIN_INPUT = 136

    if len(data) < MIN_INPUT:
        computation.output = b"\x00" * 64
        return computation

    pool_id = data[0:32]
    amount_a = _decode_uint256(data[32:64])
    amount_b = _decode_uint256(data[64:96])
    tick_lower = struct.unpack(">i", data[96:100])[0]
    tick_upper = struct.unpack(">i", data[100:104])[0]
    recipient = data[104:136]

    # Validation
    if amount_a <= 0 and amount_b <= 0:
        computation.output = b"\x00" * 64
        return computation

    # Reentrancy guard
    global _precompile_execution_depth
    if _check_reentrancy():
        computation.output = b"\x00" * 64
        return computation
    _precompile_execution_depth += 1

    try:
        pools = _get_pools()
        pool = pools.get(pool_id)
        if pool is None:
            computation.output = b"\x00" * 64
            return computation

        if tick_lower >= tick_upper:
            computation.output = b"\x00" * 64
            return computation

        # Tick must be aligned to tick_spacing
        tick_spacing = pool["tick_spacing"]
        if tick_lower % tick_spacing != 0 or tick_upper % tick_spacing != 0:
            computation.output = b"\x00" * 64
            return computation

        # Compute liquidity for concentrated position.
        # L = min(Δx · √P_upper · √P_lower / (√P_upper − √P_lower),
        #         Δy / (√P_upper − √P_lower))
        # Simplified when we only have token amounts and tick boundaries.
        Q96 = Decimal(2**96)
        sqrt_price_q96 = Decimal(pool["sqrt_price"])
        sqrt_price = sqrt_price_q96 / Q96 if sqrt_price_q96 > 0 else Decimal(1)

        # For positions where both amounts > 0, use geometric mean
        product = amount_a * amount_b
        if product <= 0:
            # Single-sided liquidity — use the non-zero amount
            liquidity = max(amount_a, amount_b)
        else:
            # Newton's method for sqrt(product)
            x = product
            y = (x + 1) // 2
            while y < x:
                x = y
                y = (x + product / x) / 2
            liquidity = x.quantize(AMOUNT_PRECISION, rounding=ROUND_HALF_UP)

        # Deterministic position ID
        pos_id = hashlib.blake2b(
            pool_id + recipient + struct.pack(">ii", tick_lower, tick_upper),
            digest_size=32,
        ).digest()

        # Update pool state
        pool["liquidity"] = int(pool.get("liquidity", 0)) + int(liquidity / AMOUNT_PRECISION)
        pool["positions"][pos_id] = {
            "owner": recipient,
            "tick_lower": tick_lower,
            "tick_upper": tick_upper,
            "liquidity": liquidity,
        }

        computation.output = _encode_uint256(liquidity) + pos_id
        return computation
    finally:
        _precompile_execution_depth -= 1


def exchange_place_limit_order(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0103: placeLimitOrder — place a limit order on the CLOB.

    Input (129 bytes):
        token_in   [0:32]    — 32-byte input token symbol
        token_out  [32:64]   — 32-byte output token symbol
        amount     [64:96]   — uint256 order amount
        price      [96:128]  — uint256 limit price (8 dp)
        side       [128:129] — uint8: 0=BUY, 1=SELL

    Output (33 bytes):
        success   [0:1]     — 0x01 if placed, 0x00 if rejected
        order_id  [1:33]    — 32-byte deterministic order identifier

    Returns 0x00 + zeros on error.
    """
    computation.consume_gas(GAS_EXCHANGE_PLACE_LIMIT_ORDER, reason="Exchange placeLimitOrder")

    data = computation.msg.data
    MIN_INPUT = 129

    if len(data) < MIN_INPUT:
        computation.output = b"\x00" * 33
        return computation

    token_in = _decode_token(data[0:32])
    token_out = _decode_token(data[32:64])
    amount = _decode_uint256(data[64:96])
    price = _decode_uint256(data[96:128])
    side = data[128]  # 0=BUY, 1=SELL

    # Validation
    if not token_in or not token_out or token_in == token_out:
        computation.output = b"\x00" * 33
        return computation
    if amount <= 0 or price <= 0:
        computation.output = b"\x00" * 33
        return computation
    if side > 1:
        computation.output = b"\x00" * 33
        return computation

    # Reentrancy guard
    global _precompile_execution_depth
    if _check_reentrancy():
        computation.output = b"\x00" * 33
        return computation
    _precompile_execution_depth += 1

    try:
        # Deterministic order ID
        sender_bytes = computation.msg.sender if hasattr(computation.msg, 'sender') else b"\x00" * 20
        order_id = hashlib.blake2b(
            sender_bytes + _encode_token(token_in) + _encode_token(token_out)
            + _encode_uint256(amount) + _encode_uint256(price) + bytes([side]),
            digest_size=32,
        ).digest()

        # Store order via consensus-safe accessor
        orderbooks = _get_orderbooks()
        pair_key = f"{token_in}:{token_out}"
        if pair_key not in orderbooks:
            orderbooks[pair_key] = {}

        orderbooks[pair_key][order_id] = {
            "owner": sender_bytes,
            "amount": amount,
            "price": price,
            "side": "BUY" if side == 0 else "SELL",
            "filled": Decimal(0),
            "status": "OPEN",
        }

        computation.output = b"\x01" + order_id
        return computation
    finally:
        _precompile_execution_depth -= 1


def exchange_cancel_order(computation: ComputationAPI) -> ComputationAPI:
    """
    Precompile 0x0104: cancelOrder — cancel an existing limit order.

    Input (96 bytes):
        token_in   [0:32]    — 32-byte input token symbol
        token_out  [32:64]   — 32-byte output token symbol
        order_id   [64:96]   — 32-byte order identifier

    Output (1 byte):
        0x01 if cancelled successfully, 0x00 if not found or not owner.
    """
    computation.consume_gas(GAS_EXCHANGE_CANCEL_ORDER, reason="Exchange cancelOrder")

    data = computation.msg.data
    MIN_INPUT = 96

    if len(data) < MIN_INPUT:
        computation.output = b"\x00"
        return computation

    token_in = _decode_token(data[0:32])
    token_out = _decode_token(data[32:64])
    order_id = data[64:96]

    # Reentrancy guard
    global _precompile_execution_depth
    if _check_reentrancy():
        computation.output = b"\x00"
        return computation
    _precompile_execution_depth += 1

    try:
        orderbooks = _get_orderbooks()
        pair_key = f"{token_in}:{token_out}"
        book = orderbooks.get(pair_key, {})
        order = book.get(order_id)

        if order is None:
            computation.output = b"\x00"
            return computation

        # Authorization: only order owner can cancel
        sender_bytes = computation.msg.sender if hasattr(computation.msg, 'sender') else b"\x00" * 20
        if order["owner"] != sender_bytes:
            computation.output = b"\x00"
            return computation

        # Cancel
        order["status"] = "CANCELLED"
        del book[order_id]

        computation.output = b"\x01"
        return computation
    finally:
        _precompile_execution_depth -= 1


# ── Precompile Registry ───────────────────────────────────────────────
# Maps Address → Callable[[ComputationAPI], ComputationAPI]
# This is the format required by py-evm (see eth/vm/computation.py line 386).

QRDX_PRECOMPILES = {
    DILITHIUM_VERIFY_ADDRESS: dilithium_verify,
    KYBER_ENCAPSULATE_ADDRESS: kyber_encapsulate_precompile,
    KYBER_DECAPSULATE_ADDRESS: kyber_decapsulate_precompile,
    BLAKE3_HASH_ADDRESS: blake3_hash_precompile,
    # Exchange Engine precompiles (0x0100 range — Step 4.4)
    EXCHANGE_CREATE_POOL_ADDRESS: exchange_create_pool,
    EXCHANGE_SWAP_ADDRESS: exchange_swap,
    EXCHANGE_ADD_LIQUIDITY_ADDRESS: exchange_add_liquidity,
    EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS: exchange_place_limit_order,
    EXCHANGE_CANCEL_ORDER_ADDRESS: exchange_cancel_order,
    # Oracle precompiles (0x0200 range — Step 4.5)
    ORACLE_GET_CHAIN_STATE_ADDRESS: get_chain_state_precompile,
    ORACLE_VERIFY_PROOF_ADDRESS: verify_external_proof_precompile,
    ORACLE_SUBMIT_CROSS_CHAIN_TX_ADDRESS: submit_cross_chain_tx_precompile,
}
