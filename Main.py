#!/usr/bin/env python3
"""Single-command SAL demonstration and research experiment runner."""
from __future__ import annotations
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
# Avoid a dependency solely to parse the two documented .env settings.
if (ROOT / '.env').is_file():
    for line in (ROOT / '.env').read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            k,v = (part.strip() for part in line.split('=', 1))
            if k in ('SAL_PROFILE','SAL_OUTPUT_ROOT'):
                os.environ.setdefault(k, v.strip("'\""))
sys.path.insert(0, str(ROOT / 'src'))

def ensure_dependencies():
    required = ('cryptography', 'numpy', 'pandas', 'matplotlib', 'yaml', 'scipy', 'psutil')
    if all(importlib.util.find_spec(k) for k in required):
        return
    if os.environ.get('SAL_BOOTSTRAPPED') == '1':
        raise SystemExit('Dependency installation failed; see README setup instructions.')
    import venv
    venv_dir = ROOT / '.venv'
    interpreter = venv_dir / 'bin' / 'python'
    if not interpreter.exists():
        venv.EnvBuilder(with_pip=True).create(venv_dir)
    subprocess.check_call([str(interpreter), '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')])
    env = dict(os.environ, SAL_BOOTSTRAPPED='1')
    raise SystemExit(subprocess.call([str(interpreter), str(ROOT / 'Main.py'), *sys.argv[1:]], env=env))

def main():
    p = argparse.ArgumentParser(description='Selective Auditability Ledger')
    p.add_argument('--profile', choices=('quick', 'research'), default=os.environ.get('SAL_PROFILE', 'quick'))
    p.add_argument('--config', default=str(ROOT / 'configs' / 'default.yaml'))
    p.add_argument('--seed', type=int, default=2026)
    p.add_argument('--output-root', default=os.environ.get('SAL_OUTPUT_ROOT', str(ROOT / 'output')))
    p.add_argument('--experiments', nargs='+', choices=('E1','E2','E3','E4','E5','E6','E7'), default=['E1','E2','E3','E4','E5','E6','E7'])
    p.add_argument('--test', action='store_true')
    args = p.parse_args()
    ensure_dependencies()
    if args.test:
        raise SystemExit(subprocess.call([sys.executable, '-m', 'unittest', 'discover', '-s', str(ROOT / 'tests'), '-v'], cwd=ROOT))
    from sal.experiments import execute
    path = execute(args)
    print(f'\nSAL outputs saved to: {path}')

if __name__ == '__main__':
    main()
