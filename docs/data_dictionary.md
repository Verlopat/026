# Synthetic cloud-access event schema

`event_id` (synthetic unique label), `subject_id` (synthetic user), `actor_id`,
`actor_role`, `resource_id`, `resource_class`, `action`, `outcome`,
`timestamp_exact` (UTC ISO 8601 text), `source_ip` (RFC 5737 documentation-only
192.0.2.0/24), `device_id`, `policy_version`, `issuer_id`, and `payload`.

The event generator uses no actual users, production resource names or network
addresses. Seeded `random.Random` controls event content; `secrets`/`os.urandom`
controls real cryptographic salts and AES keys. Cryptographic bytes are correctly
**not deterministic** when the dataset seed is repeated.

The local SQLite `records` table contains sensitive material before erasure,
including temporary plaintext subject indexes and per-record wrapped data
keys. The ephemeral wrapping master key lives in process memory only. This is a
single-process research prototype and not a secure production key manager.
Record content lives off-chain; batch anchors contain roots, count, coarse
hour windows and policy only. Each retained event proof has a pseudonymous
record reference, commitment and field-root commitment. The `deletion` table
retains a signed deletion-workflow certificate.
