"""Independent, read-only verification of exported SAL audit packages."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .core import SAL

def main():
    p=argparse.ArgumentParser(description='Verify exported SAL proof against a trusted pinned public key')
    p.add_argument('proof',type=Path)
    p.add_argument('--key',required=True,type=Path,help='Trusted Ed25519 raw public key in hex')
    p.add_argument('--full',action='store_true',help='Require full original-event opening')
    p.add_argument('--post',action='store_true',help='Verify signed deletion certificate')
    args=p.parse_args()
    data=json.loads(args.proof.read_text())
    pub=args.key.read_text().strip()
    if args.post:
        ok=SAL.verify_post(data['proof'],data['certificate'],pub)
    else:
        ok=SAL.verify_proof(data['proof'] if 'proof' in data else data,pub,require_full=args.full)
    print('VERIFIED' if ok else 'INVALID')
    raise SystemExit(0 if ok else 1)

if __name__=='__main__':main()
