# Threat model and security claims

## Environment

SAL runs a **local permissioned-ledger simulation** backed by SQLite. A single
publisher signs each anchor using Ed25519. Proof verifiers must obtain and pin
the publisher public key from a trustworthy, separate channel. The public key
included by an untrusted claimant is **not** a trust anchor.

## In scope

- Unauthorized modification of AES-GCM ciphertexts, nonces and associated data.
- Tampering with field values, per-field openings, Merkle sibling nodes or batch roots.
- Manipulating, reordering, or replacing ledger anchors after publication without
  obtaining the issuer's signing key.
- Altering or misassigning signed deletion workflow certificates.
- Offline candidate-matching attacks against ledger hashes; secret high-entropy
  salts are assumed unknown to the attacker.
- Uniqueness or linkability proxies derived from simulated event metadata.

## Out of scope

- Dishonest source applications inventing events prior to commitment.
- Compromise of the issuing signing key, encryption keys, SQLite administrator or
  OS root user; public-key pinning failures.
- Proof that deletion occurred on all backups, replicas, endpoints or recipients.
- Resistant key destruction in physical memory, DB WAL, swap or backup copies.
- Deletion authorization under live GDPR workflows.
- Zero-knowledge proofs, Byzantine consensus, Fabric deployment, real cloud logs.

## Privacy and erasure qualification

Salts, ciphertexts, commitments, Merkle roots, even coarse timestamps may be
personal data depending on surrounding context. SAL's signed certificate
establishes **that the configured prototype logged a deletion workflow**, not
that universal erasure is legally or physically established. SQL `secure_delete`
helps reduce recoverability of locally deleted SQLite content but does not prove
secure wiping on SSD, WAL copies or backups. Deletion removes local payload,
record key, nonce, event salt, field-opening salts and subject lookup entry.
A pseudonymous record key and a commitment-bound inclusion proof remain.

## Auditability boundaries

- Pre-erasure full-content verification is available only to an authorized caller
  and binds the canonical event to its salted event commitment.
- Pre-erasure partial-field disclosure uses per-field salted hashes and a
  separate Merkle root that is combined with the full-content commitment in the
  batch leaf. This is not a zero-knowledge proof.
- Post-erasure verification checks historical commitment inclusion and a later
  signed certificate; it cannot reconstruct erased personal payloads.
- The local issuer can refuse to present records or rewrite the local log if the
  verification key is compromised. There is no independent remote witness.
