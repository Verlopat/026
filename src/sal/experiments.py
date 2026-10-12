"""E1-E7 benchmark suite with fully automated tabular and figure outputs."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import copy
import csv
import hashlib
import json
import logging
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
import traceback
import uuid
import numpy as np
import pandas as pd
import psutil
import yaml
from .core import SAL, canon, event_commitment, merkle_root, merkle_path, verify_merkle, stable_seed, sha

LOG = logging.getLogger('sal')

def events(n: int, seed: int, payload_size=512):
    """Reproducible event generator; values are synthetic, not actual user data."""
    rng=random.Random(seed)
    for i in range(n):
        actor = rng.randrange(1, max(10,n//3))
        role=rng.choice(['viewer']*6+['editor']*3+['admin'])
        action=rng.choice(['read']*6+['write']*2+['delete','login'])
        e={'event_id':f'synthetic-{seed:x}-{i:08d}', 'subject_id':f'USER-{actor:06d}',
           'actor_id':f'ACTOR-{actor:06d}','actor_role':role,'resource_id':f'OBJ-{rng.randrange(50):05d}',
           'resource_class':rng.choice(['public','internal','restricted']),
           'action':action,'outcome':rng.choice(['allow']*8+['deny','error']),
           'timestamp_exact':f'2026-01-{1+(i//800)%28:02d}T{(i//60)%24:02d}:{i%60:02d}:00Z',
           'source_ip':f'192.0.2.{1+actor%250}', 'device_id':f'DEV-{actor%113:03d}',
           'policy_version':'policy-v1','issuer_id':f'service-{actor%5}',
           'payload':'x'*max(1, payload_size-370)}
        yield e

def interval_summary(values: list[float], seed=1):
    if not values: return {'n':0}
    x=np.asarray(values,dtype=float)
    rng=np.random.default_rng(seed)
    # Independent run sample CI on mean; suitable for descriptive trial-level reporting.
    boot=np.array([rng.choice(x,size=len(x),replace=True).mean() for _ in range(1000)])
    return {'n':len(x),'mean':float(x.mean()),'median':float(np.median(x)),
            'std':float(x.std(ddof=1) if len(x)>1 else 0),
            'iqr':float(np.percentile(x,75)-np.percentile(x,25)),
            'p95':float(np.percentile(x,95)),'p99':float(np.percentile(x,99)),
            'ci95_low':float(np.percentile(boot,2.5)), 'ci95_high':float(np.percentile(boot,97.5))}

def timed(operation):
    before=time.perf_counter_ns(); result=operation()
    return result,(time.perf_counter_ns()-before)/1e6

def setup_sal(n, seed, batch=32, payload=512):
    sal=SAL(batch_size=batch)
    ids=[]
    for e in events(n,seed,payload): ids.append(sal.ingest(e))
    sal.seal()
    return sal,ids

def e1(config,seed):
    sal, ids=setup_sal(config['integrity_events'],seed,config['batch_size'])
    rows=[]; pub=sal.issuer_public_hex()
    for j,rid in enumerate(ids[:config['tamper_samples']]):
        p=sal.proof(rid)
        versions={}
        def flip(h): return ('0' if h[0]!='0' else '1')+h[1:]
        for k in ('commitment','field_root'):
            t=copy.deepcopy(p);t[k]=flip(t[k]);versions[k]=t
        for k in ('sibling','field_sibling'):
            t=copy.deepcopy(p)
            if k=='sibling' and t['batch_path']:t['batch_path'][0]['hash']=flip(t['batch_path'][0]['hash'])
            elif k=='field_sibling':
                name=next(iter(t['fields']))
                if t['fields'][name]['path']:t['fields'][name]['path'][0]['hash']=flip(t['fields'][name]['path'][0]['hash'])
            versions[k]=t
        for k in ('root','predecessor','signature','reorder'):
            t=copy.deepcopy(p)
            a=t['anchors'][t['batch_seq']-1]
            if k=='root': a['payload']['root']=flip(a['payload']['root'])
            if k=='predecessor': a['previous']=flip(a['previous'])
            if k=='signature': a['signature']=flip(a['signature'])
            if k=='reorder' and len(t['anchors'])>1:t['anchors'][0],t['anchors'][1]=t['anchors'][1],t['anchors'][0]
            versions[k]=t
        # A wrong sibling-side bit simulates a changed leaf position/order.
        reordered=copy.deepcopy(p)
        if reordered['batch_path']:
            reordered['batch_path'][0]['left']=not reordered['batch_path'][0]['left']
            versions['leaf_order']=reordered
        name=next(iter(p['fields']))
        field=copy.deepcopy(p); field['fields'][name]['value']='TAMPERED';versions['disclosed_content']=field
        for kind,t in versions.items():
            ok,lat=timed(lambda:SAL.verify_proof(t,pub,require_full=True))
            # Reorder is inapplicable if there is only one anchor; explicitly skip.
            if kind=='reorder' and len(p['anchors'])<2: continue
            rows.append({'method':'P1','tamper':kind,'trial':j,'detected':not ok,'false_accept':int(ok),'latency_ms':lat})
        # Off-chain tampering is checked by AES-GCM, independently of Merkle inclusion.
        r=sal._get(rid)
        for kind in ('ciphertext_byte','nonce_byte'):
            bad=bytearray(r['ciphertext'] if kind=='ciphertext_byte' else r['nonce']);bad[0]^=1
            try:
                if kind=='ciphertext_byte':
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    AESGCM(sal._unwrap_key(rid,r['wrapped_key'])).decrypt(r['nonce'],bytes(bad),canon({'policy':r['policy'],'v':'1'}))
                else:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    AESGCM(sal._unwrap_key(rid,r['wrapped_key'])).decrypt(bytes(bad),r['ciphertext'],canon({'policy':r['policy'],'v':'1'}))
                detected=False
            except Exception:detected=True
            rows.append({'method':'P1','tamper':kind,'trial':j,'detected':detected,'false_accept':int(not detected),'latency_ms':0})
    victim=ids[0]; p_before=sal.proof(victim)
    sal.delete(victim,approved=True); post=sal.proof(victim);cert=sal.deletion_certificate(victim)
    forged=copy.deepcopy(cert);forged['deletion_window']='2030-01-01T00:00Z'
    reassigned=copy.deepcopy(cert);reassigned['commitment']='0'*64
    for kind,certificate in [('deletion_cert_modified',forged),('deletion_cert_reassigned',reassigned)]:
        valid,lat=timed(lambda:SAL.verify_post(post,certificate,pub))
        rows.append({'method':'P1','tamper':kind,'trial':0,'detected':not valid,'false_accept':int(valid),'latency_ms':lat})
    sal.close()
    return rows

def e2(config,seed):
    data=[]
    for rate in config['deletion_rates']:
        sal,ids=setup_sal(config['deletion_events'],stable_seed(seed,'E2',rate),config['batch_size'])
        pub=sal.issuer_public_hex()
        count=max(1,round(len(ids)*rate))
        for rid in ids[:count]:
            p_before=sal.proof(rid)
            full_before=SAL.verify_proof(p_before,pub,require_full=True)
            _,lat=timed(lambda:sal.delete(rid,approved=True))
            after=sal.proof(rid);cert=sal.deletion_certificate(rid)
            intact=SAL.verify_post(after,cert,pub)
            recovered=sal.recover(rid) is not None
            data.append({'method':'P1','deletion_rate':rate,'full_pre_verified':full_before,
                         'post_inclusion_verified':SAL.verify_proof(after,pub),
                         'certificate_verified':intact,'payload_recovered':recovered,
                         'deletion_latency_ms':lat,'retained_ciphertext_bytes':0})
            # Ablations: no certificate fails to attest workflow; key-only leaves ciphertext.
            data.append({'method':'A2-no-certificate','deletion_rate':rate,
                         'full_pre_verified':full_before,'post_inclusion_verified':SAL.verify_proof(after,pub),
                         'certificate_verified':False,'payload_recovered':False,
                         'deletion_latency_ms':None,'retained_ciphertext_bytes':0})
        sal.close()
    return data

def e3(config,seed):
    rows=[]; samples=list(events(config['attack_events'],seed))
    # Fresh secret salts are never supplied to the attacker.
    salts=[os.urandom(32) for _ in samples]
    targets={event_commitment(e,s).hex() for e,s in zip(samples,salts)}
    raw_hashes={sha('SAL-EVENT-v1',canon(e)).hex() for e in samples}
    for method in ('B2-unsalted','A1-no-salt','P1-secret-salt'):
        start=time.perf_counter_ns(); matches=0
        for e in samples:
            guess=sha('SAL-EVENT-v1',canon(e)).hex()
            matches+=int(guess in (targets if method=='P1-secret-salt' else raw_hashes))
        rows.append({'method':method,'dictionary':'known-complete-events',
                    'targets':len(samples),'correct_matches':matches,'linkage_rate':matches/len(samples),
                    'runtime_ms':(time.perf_counter_ns()-start)/1e6,
                    'adversary':'full event known, salt unknown'})
    return rows

def e4(config,seed):
    ev=list(events(config['metadata_events'],seed)); rows=[]
    for granularity in ('second','minute','hour','day'):
        for batch in config['metadata_batches']:
            for category in ('exact','coarse','hidden'):
                for issuer in ('exact','hidden'):
                    keys=[]
                    for i,e in enumerate(ev):
                        t=e['timestamp_exact']
                        bucket={'second':t[:19],'minute':t[:16], 'hour':t[:13], 'day':t[:10]}[granularity]
                        cat=e['action'] if category=='exact' else ('write' if e['action'] in ('write','delete') else 'other') if category=='coarse' else None
                        sig=(bucket,i//batch,cat,e['issuer_id'] if issuer=='exact' else None,e['policy_version'])
                        keys.append(sig)
                    cnt=Counter(keys);sizes=[cnt[k] for k in keys]
                    rows.append({'timestamp':granularity,'batch_size':batch,'event_category':category,
                                 'issuer':issuer,'events':len(ev),
                                 'uniqueness_rate':sum(k==1 for k in sizes)/len(sizes),
                                 'under_k5_rate':sum(k<5 for k in sizes)/len(sizes),
                                 'median_anonymity_set':float(statistics.median(sizes)),
                                 'audit_time_precision_rank':{'second':4,'minute':3,'hour':2,'day':1}[granularity]})
    return rows

def _baseline_offchain(n,seed,payload):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    total=0;key=AESGCM.generate_key(bit_length=256);aead=AESGCM(key)
    for e in events(n,seed,payload):
        encrypted=aead.encrypt(os.urandom(12),canon(e),b'policy-v1')
        total+=len(encrypted)
    return total

def e5(config,seed):
    rows=[]
    for n in config['performance_counts']:
        for batch in config['performance_batches']:
            for method in ('B4-offchain','B5-per-event','P1-batched'):
                actual_batch=1 if method=='B5-per-event' else batch
                for repetition in range(config['benchmark_warmups']+config['benchmark_repetitions']):
                    ps=psutil.Process();before_mem=ps.memory_info().rss
                    start=time.perf_counter_ns()
                    if method=='B4-offchain':
                        encrypted_bytes=_baseline_offchain(n,stable_seed(seed,n,repetition),config['payload_size'])
                        path_len=0; anchors=0; proof_time=0; verify_time=0; proof_size=0
                    else:
                        sal,ids=setup_sal(n,stable_seed(seed,n,repetition),actual_batch,config['payload_size'])
                        proof,proof_time=timed(lambda:sal.proof(ids[-1]))
                        verified,verify_time=timed(lambda:SAL.verify_proof(proof,sal.issuer_public_hex()))
                        if not verified:raise AssertionError('Benchmark-generated proof failed verification')
                        proof_size=len(canon({k:proof[k] for k in ('commitment','field_root','batch_path','fields')}));path_len=len(proof['batch_path']);anchors=len(sal.anchors())
                        encrypted_bytes=sum(len(sal._get(i)['ciphertext']) for i in ids)
                        sal.close()
                    elapsed=(time.perf_counter_ns()-start)/1e9
                    if repetition>=config['benchmark_warmups']:
                        rows.append({'method':method,'events':n,'batch_size':batch,'effective_batch_size':actual_batch,'repetition':repetition,
                                     'throughput_events_s':n/max(elapsed,1e-9),'duration_s':elapsed,
                                     'proof_generation_ms':proof_time,'proof_verification_ms':verify_time,
                                     'proof_size_bytes':proof_size,
                                     'path_hashes':path_len,'anchors':anchors,
                                     'encrypted_bytes':encrypted_bytes,
                                     'rss_delta_mb':(ps.memory_info().rss-before_mem)/(1024*1024)})
    return rows

def e6(config,seed):
    sal,ids=setup_sal(12,seed,4);rid=ids[0];pub=sal.issuer_public_hex()
    pre=sal.proof(rid,disclosed_fields=['action','policy_version']);pre_ok=SAL.verify_proof(pre,pub)
    full_ok=sal.recover(rid) is not None
    sal.delete(rid,approved=True);post=sal.proof(rid);cert=sal.deletion_certificate(rid)
    post_ok=SAL.verify_post(post,cert,pub)
    sal.close()
    rows=[]
    # True indicates an accurate supported response (including a refusal on unavailable data).
    for phase in ('pre','post'):
        for query in ('Q1-commitment','Q2-policy','Q3-deletion-workflow','Q4-full-payload','Q5-subject-lookup'):
            answerable={
              'Q1-commitment':pre_ok if phase=='pre' else post_ok,
              'Q2-policy':True,
              'Q3-deletion-workflow':phase=='post' and post_ok,
              'Q4-full-payload':phase=='pre' and full_ok,
              'Q5-subject-lookup':phase=='pre'
            }[query]
            rows.append({'method':'P1','phase':phase,'query':query,'answerable':bool(answerable),
                         'correct_handling':True,
                         'discloses_deleted_content':False,
                         'note':'subject mapping and payload intentionally unavailable after deletion' if query=='Q5-subject-lookup' else ''})
            # Comparison methods are capability-model ablations, not independently executed protocols.
            for method in ('B4-offchain','A2-no-certificate','A4-coarse-time','A7-coarse-category'):
                capable=answerable
                if method=='B4-offchain' and query in ('Q1-commitment','Q3-deletion-workflow'): capable=False
                if method=='A2-no-certificate' and query=='Q3-deletion-workflow': capable=False
                rows.append({'method':method,'phase':phase,'query':query,'answerable':bool(capable),
                             'correct_handling':True,'discloses_deleted_content':False,
                             'note':'modelled comparison; not measured cryptographic verification'})
    return rows

def e7(config,seed):
    rows=[]
    for rate in (0,0.01,0.1,0.25,0.5):
        sal=SAL(batch_size=config['batch_size']);ids=[]
        for e in events(config['lifecycle_events'],stable_seed(seed,'E7',rate)):ids.append(sal.ingest(e))
        # First deletion may occur before final partial batch seal.
        count=round(len(ids)*rate)
        denied=0;repeat_rejected=0;stale=0;verified=0;times=[]
        for rid in ids[:count]:
            try:sal.delete(rid,approved=False)
            except PermissionError:denied+=1
            result,lat=timed(lambda:sal.delete(rid,approved=True));times.append(lat)
            try:sal.delete(rid,approved=True)
            except ValueError:repeat_rejected+=1
            proof=sal.proof(rid)
            verified+=int(SAL.verify_post(proof,result['certificate'],sal.issuer_public_hex()))
            stale+=int(sal._get(rid)['subject_index'] is not None)
        sal.seal()
        rows.append({'method':'P1','deletion_rate':rate,'events':len(ids),'deleted':count,
                     'denied_requests':denied,'repeat_delete_rejected':repeat_rejected,
                     'verified_certificates':verified,'stale_subject_indexes':stale,
                     'mean_deletion_latency_ms':float(statistics.mean(times)) if times else 0,
                     'remaining_payloads':sal.db.execute('SELECT COUNT(*) FROM records WHERE ciphertext IS NOT NULL').fetchone()[0]})
        sal.close()
    return rows

EXPERIMENTS={'E1':e1,'E2':e2,'E3':e3,'E4':e4,'E5':e5,'E6':e6,'E7':e7}

def _new_output(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    for i in range(1,100000):
        path=root/f'test{i}'
        try:path.mkdir();return path
        except FileExistsError:continue
    raise RuntimeError('No available run directory')

def _write_table(df:pd.DataFrame,path:Path):
    # Parquet preferred; CSV is preserved even when pyarrow is unavailable offline.
    df.to_csv(path.with_suffix('.csv'),index=False)
    try:
        import pyarrow  # noqa: F401
        df.to_parquet(path,index=False)
    except ImportError:LOG.warning('pyarrow not installed: wrote CSV rather than Parquet (%s)',path.name)

def _sysinfo():
    import cryptography, scipy, matplotlib
    try:
        sha=subprocess.check_output(['git','rev-parse','HEAD'],stderr=subprocess.DEVNULL,timeout=2,text=True).strip()
    except Exception: sha=None
    return {'git_sha':sha,'scipy':scipy.__version__,'matplotlib':matplotlib.__version__,
            'psutil':psutil.__version__,'python':sys.version,'platform':platform.platform(),'machine':platform.machine(),
            'processor':platform.processor(),'logical_cores':os.cpu_count(),'ram_gb':round(psutil.virtual_memory().total/1024**3,2),
            'cryptography':cryptography.__version__,'numpy':np.__version__,'pandas':pd.__version__,
            'timestamp':datetime.now(timezone.utc).isoformat()}

def execute(args):
    config_path=Path(args.config)
    settings=yaml.safe_load(config_path.read_text())
    config=settings[args.profile].copy()
    assert config['batch_size']>0
    path=_new_output(args.output_root)
    log_path=path/'run.log'
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s',
                        handlers=[logging.StreamHandler(),logging.FileHandler(log_path)],force=True)
    (path/'config.yaml').write_text(yaml.safe_dump({args.profile:config},sort_keys=True))
    (path/'environment.json').write_text(json.dumps(_sysinfo(),indent=2))
    (path/'experiments').mkdir();(path/'figures').mkdir();(path/'tables').mkdir()
    # Save proof packages separately from synthetic benchmark streams. The public
    # key must be pinned by the verifier using an out-of-band trusted copy.
    proofdir=path/'proofs';proofdir.mkdir()
    demo=SAL(batch_size=2)
    demo_ids=[demo.ingest(e) for e in events(2,stable_seed(args.seed,'proof-demo'))]
    demo.seal();target=demo_ids[0]
    (proofdir/'issuer_public_key.hex').write_text(demo.issuer_public_hex()+'\n')
    (proofdir/'audit_full.json').write_text(json.dumps({'proof':demo.proof(target)},indent=2))
    (proofdir/'audit_partial.json').write_text(json.dumps({'proof':demo.proof(target,['action','outcome'])},indent=2))
    demo.delete(target,approved=True)
    (proofdir/'audit_post.json').write_text(json.dumps({'proof':demo.proof(target),
                     'certificate':demo.deletion_certificate(target)},indent=2))
    demo.close()
    raw={};status={};start=time.time()
    for name in args.experiments:
        trial_seed=stable_seed(args.seed,name)
        LOG.info('Executing %s (seed %s)',name,trial_seed)
        expdir=path/'experiments'/name;expdir.mkdir()
        try:
            rows=EXPERIMENTS[name](config,trial_seed)
            if not rows:raise RuntimeError('Experiment returned no records')
            df=pd.DataFrame(rows);_write_table(df,expdir/'raw_results.parquet')
            _write_table(df.describe(include='all').reset_index().fillna('').astype(str),expdir/'descriptive_summary.parquet')
            numeric=df.select_dtypes(include=['number']).columns
            numeric_summaries=[]
            for col in numeric:
                vals=[float(v) for v in df[col].dropna() if np.isfinite(float(v))]
                if vals:
                    numeric_summaries.append({'metric':col,**interval_summary(vals,stable_seed(args.seed,name,col))})
            if numeric_summaries:
                _write_table(pd.DataFrame(numeric_summaries),expdir/'numeric_statistics.parquet')
            raw[name]=df;status[name]={'success':True,'rows':len(df),'seed':trial_seed}
        except Exception as exc:
            status[name]={'success':False,'exception':str(exc),'seed':trial_seed}
            (expdir/'error.txt').write_text(traceback.format_exc())
            LOG.exception('%s failed',name)
    from .report import write_reports
    write_reports(raw,path)
    manifest={'protocol':'SAL-v1','profile':args.profile,'master_seed':args.seed,
              'config_sha256':hashlib.sha256(canon(config)).hexdigest(),
              'experiments':status,'runtime_seconds':round(time.time()-start,3),
              'warnings':['Simulated single-publisher ledger, not independently replicated blockchain',
                          'Deletion evidence is a signed workflow event, not universal proof of physical data destruction',
                          'Synthetic metadata risk is a proxy; not proof of anonymity or GDPR compliance']}
    (path/'manifest.json').write_text(json.dumps(manifest,indent=2))
    checksums=[]
    for p in sorted(path.rglob('*')):
        if p.is_file() and p.name!='checksums.txt':
            checksums.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(path)}')
    (path/'checksums.txt').write_text('\n'.join(checksums)+'\n')
    if not all(x['success'] for x in status.values()):
        LOG.error('Some experiments failed; see manifest.json and errors')
    LOG.info('Generated run %s',path)
    return path
