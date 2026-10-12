# Selective Auditability Ledger (SAL)

A locally reproducible research prototype for privacy-minimized, tamper-evident
**cloud-access audit trails**. SAL encrypts event payloads with per-record
AES-256-GCM keys in an off-chain SQLite store, anchors salted full-event and
per-field commitments through batched Merkle trees in a signed append-only
ledger simulation, and issues signed deletion-workflow certificates.

SAL supports verifiable authorized selective-field disclosure **before** a
delete request, and historical commitment inclusion plus deletion-workflow
evidence **after** deletion. It is **not** a deployed blockchain, a production
key management system, a zero-knowledge proof system, or certification of GDPR
compliance. No personal data should be supplied to the experimental runner.

## Requirements and quick start

On Ubuntu Linux, confirm the environment:

```bash
python3 --version
python3 -m pip --version
git --version
```

Python 3.12+ is supported. Use a working internet connection the first time if
Python packages are not installed.

```bash
git clone https://github.com/Verlopat/026.git
cd 026
python3 Main.py
```

`Main.py` checks its dependencies, creates `.venv` and installs pinned-range
requirements automatically when necessary, and executes **E1–E7 together**.
No Docker, GPU, payment account or real cloud database is needed. A local
`.env` file can override `SAL_PROFILE` and `SAL_OUTPUT_ROOT` (start from
`.env.example`). The repository does not ship or require secrets for the
simulation. Cryptographic keys are generated freshly in each run.

For manual setup or troubleshooting:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python3 Main.py
```

Run tests in one command:

```bash
python3 Main.py --test
```

## Output folders

Every invocation creates a **new non-overwriting** directory. For example:

```text
output/
├── test1/
│   ├── manifest.json
│   ├── environment.json
│   ├── config.yaml
│   ├── checksums.txt
│   ├── run.log
│   ├── proofs/
│   │   ├── issuer_public_key.hex
│   │   ├── audit_full.json
│   │   ├── audit_partial.json
│   │   └── audit_post.json
│   ├── experiments/
│   │   ├── E1/ ... E7/
│   │   └── E7/raw_results.csv
│   ├── figures/ (F1–F5, PNG and PDF)
│   ├── tables/ (T1–T6, CSV)
│   └── statistics.json
└── test2/ (next complete run)
```

Each E-series experiment gets `raw_results.csv` and descriptive results. With
`pyarrow` installed, the same rows are also saved as genuine `.parquet` files.
If `pyarrow` is unavailable offline, the program logs a warning and preserves
CSV output instead of claiming Parquet was generated. `checksums.txt` records
SHA-256 file hashes; `manifest.json` lists successes and failures explicitly.

Run one or several experiments without overwriting previous results:

```bash
python3 Main.py --experiments E1 E2
python3 Main.py --experiments E3 E4 E5 E6 E7 --seed 2027
python3 Main.py --profile research
python3 Main.py --config configs/default.yaml --output-root /tmp/sal-runs
```

The default `quick` profile deliberately uses small datasets to keep a local
end-to-end smoke run short. The **research** profile configures 10,000-event
integrity testing, 100,000-event privacy/deletion scenarios, multiple batch
sizes and 10 measured repetitions after five warmups for performance. The
research profile can take substantial CPU time and disk. Configurable scales
and experiment definitions are in `configs/default.yaml`; large 1,000,000-event
stress tests should be configured only after assessing machine capacity.

## Research components and deliverables

| Experiment | Purpose | Key generated result |
| --- | --- | --- |
| E1 | Malformed proof, ciphertext, chain and deletion-certificate rejection | T1 |
| E2 | Erasure workflow and post-erasure verifiability | T2 |
| E3 | Offline known-event candidate matching, secret versus missing salt | F1, T3 |
| E4 | Timestamp, category, issuer and batch linkability proxies | F2, T4 |
| E5 | Encrypted off-chain baseline, per-event anchor, Merkle batching | F3, F4, T5 |
| E6 | Pre/post audit query capability matrix | T6 |
| E7 | Unapproved/repeated requests, varying deletion rates, lifecycle behavior | E7_lifecycle.csv |

F5 visualizes the state transition between ingest, authorized audit, deletion,
and certificate verification. SHA-256 hash framing, encryption, signature,
commitment, Merkle, and proof verification use separate functions in `core.py`.

**Experimental comparators:** B4 (encrypted off-chain only), B5 (per-event
anchor), and P1 (SAL batched) are run in E5. B2/A1 (no salt) versus P1 is run
in E3. In E2, A2 (no deletion certificate) is a capability ablation. In E6,
B4, A2, A4 and A7 are *modelled capability comparisons* rather than separate
verified protocol implementations. Other suggested variants (B1, B3, A3,
A5, A6, A8) are not independent full-system baselines in this MVP; do not cite
prototype outputs as if every proposed competitive design had been executed.

**Statistical reporting:** exact integrity/detection counts; Wilson intervals
for linkage rates; per-trial latency, throughput and resource rows; median,
mean, IQR, SD, bootstrap confidence interval in code, and paired Wilcoxon
comparisons with Holm correction where E5 matched samples permit them. For a
paper-level study, verify statistical independence and implement the remaining
independent baselines before asserting comparative superiority.

## Verify exported evidence without the original SQLite store

All proof packages use **synthetic records**. An independent verifier must
obtain and pin the publisher's public key through a trusted channel rather
than accept an arbitrary key from a prover.

```bash
export PYTHONPATH=src
python3 -m sal.verify output/test1/proofs/audit_full.json \
    --key output/test1/proofs/issuer_public_key.hex --full
python3 -m sal.verify output/test1/proofs/audit_partial.json \
    --key output/test1/proofs/issuer_public_key.hex
python3 -m sal.verify output/test1/proofs/audit_post.json \
    --key output/test1/proofs/issuer_public_key.hex --post
```

Each command prints `VERIFIED` or `INVALID` and uses the exit code to indicate
success/failure. After erasure, the payload and field salts are gone from the
normal store; only commitment and workflow artifacts remain.

## Security and privacy assumptions

- Full event commitment: `H("SAL-EVENT-v1", salt, Canon(event))`.
- Selective-field commitment: separate salted hash for each field, with a field
  Merkle root bound jointly with the full event commitment in a batch leaf.
- Batch root anchored in predecessor-hash chain with Ed25519 issuer signatures.
- AES-256-GCM per-record keys/nonces; each data key is wrapped with an
  ephemeral, in-process master key and its ciphertext stored in SQLite before
  deletion. This is **not** an HSM or production KMS.
- Approved erasure removes local ciphertext, nonce, key, event/field salts and
  subject lookup. Signed deletion record remains.
- After erasure, a verifier can prove only that a commitment was anchored and
  a matching workflow certificate was appended. It **cannot** establish that
  all external replicas, backups, OS caches or recipients physically erased
  data. Ledger time windows are publisher claims, not independent trusted
  timestamps.
- Retained commitments, windows and deletion certificates may themselves be
  linkable data and must be reviewed in a real GDPR application.

Read [`docs/threat_model.md`](docs/threat_model.md),
[`docs/protocol_spec.md`](docs/protocol_spec.md) and
[`docs/data_dictionary.md`](docs/data_dictionary.md) before interpreting
results. The sample log schema includes RFC 5737 documentation IP addresses
only and no real personally identifiable data. Risks include signing-key
compromise, dishonest event issuers, and the absence of consensus or witnessed
append-only history. No production guarantees are asserted.

## Implementation layout

```text
026/
├── Main.py
├── requirements.txt
├── requirements.in
├── pyproject.toml
├── .env.example
├── .gitignore
├── LICENSE
├── configs/default.yaml
├── src/sal/
│   ├── __init__.py
│   ├── core.py
│   ├── experiments.py
│   ├── report.py
│   └── verify.py
├── tests/test_core.py
├── tests/test_experiments.py
└── docs/
    ├── threat_model.md
    ├── protocol_spec.md
    └── data_dictionary.md
```

The entry point executes the complete default pipeline and generates all
supported outputs. Optional research/verification commands are provided for
inspection, not needed to start the workflow. Source code and configuration
are intended for version control, while generated `output/` directories and
runtime data are ignored by Git.
