# Protocol definition (SAL-v1 prototype)

All hashes use SHA-256 with ASCII domain tag, zero delimiter, and unsigned 64-bit
big-endian length-prefix for **each** encoded component. Canonical JSON uses NFC,
UTF-8, sorted keys and compact separators. Canonicalization rejects unsupported
values and non-finite floats. No timestamps are inferred in the event commit.

For event `e`, sample fresh 32-byte event salt `r`, AES-256-GCM per-record key `K`
and 12-byte nonce `N`. Encrypt `Canon(e)` with AAD containing policy/version.
The event's whole-content commitment is
`c = H("SAL-EVENT-v1", r, Canon(e))`.

For every sorted event field `name`, sample independent 32-byte salt `s_name`
and form `f_name = H("SAL-FIELD-v1", name, s_name, Canon(value))`.
Let `F_root` be the binary Merkle root of these field commitments.
The event leaf in a batch is `H("SAL-LEAF-v1", c, F_root)`.

For each batch, the publisher signs an anchor with the root, count, coarse
batch time window, and its predecessor digest. Odd Merkle widths duplicate the
last leaf. Parent nodes use `H("SAL-NODE-v1", left, right)`.

**Full proof:** disclose all fields and field salts, event salt, event Merkle
path, batch Merkle path, and signed anchor chain. The verifier recomputes both
`c` and `F_root`, and checks the pinned issuer Ed25519 public key.

**Partial proof:** disclose only permitted field/value/salt/path tuples, the
field root, the event commitment, the batch Merkle path and signed anchors.
The verifier checks each opened field against `F_root`, and checks the pair
`(c, F_root)` against the batch root. It cannot independently recompute `c`
without an entire event opening. The signed batch leaf binds the two commitments
at ingestion; it does not prove that omitted fields met semantic constraints.

**Erasure:** require an authorization decision (modelled as `approved=True`),
append a certificate `d = H("SAL-DELETION-v1", Canon(body))`, bind it to the
original commitment and a separately salted request digest, and sign its anchor.
Within one SQLite transaction, null out local encrypted payload, nonce, key,
salts and subject lookup. Original signed anchor and Merkle inclusion proof remain.

**Post-erasure proof:** verify the original signed batch, Merkle path,
original commitment and later signed deletion certificate. No original content
is disclosed or reconstructed. Ledger hash chaining and source signatures do
not establish trusted wall-clock timestamps without an independent timestamping
service or witness.

## Invariants

1. Changed cryptographic paths or signed anchors are rejected.
2. Deleted payloads are unavailable through ordinary retrieval.
3. Unapproved erasure requests fail.
4. A deletion certificate never recreates erased record content.
5. A certificate for commitment A cannot be reassigned to commitment B.
6. The retention of commitment-derived identifiers has residual linkage risk.
