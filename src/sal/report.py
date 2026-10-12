"""Publication-oriented plots F1-F5 and auditability tables T1-T6."""
from __future__ import annotations
import json
import statistics
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy.stats import wilcoxon, binomtest


def _save(fig,dest:Path):
    fig.tight_layout();fig.savefig(str(dest.with_suffix('.png')),dpi=160)
    fig.savefig(str(dest.with_suffix('.pdf')))
    plt.close(fig)


def write_reports(raw:dict[str,pd.DataFrame],out:Path):
    tables=out/'tables'; figs=out/'figures'
    stats={}
    if 'E1' in raw:
        e=raw['E1']
        t=e.groupby('tamper').agg(tests=('detected','count'),detected=('detected','sum'),
                                   false_accepts=('false_accept','sum'),median_latency_ms=('latency_ms','median')).reset_index()
        t['detection_rate']=t['detected']/t['tests']
        t.to_csv(tables/'T1_integrity.csv',index=False)
        stats['E1_exact']={'modified_tested':int(e['detected'].count()),'false_accepts':int(e.false_accept.sum())}
    if 'E2' in raw:
        e=raw['E2']
        t=e.groupby(['method','deletion_rate']).agg(trials=('payload_recovered','count'),
             recovery_rate=('payload_recovered','mean'),post_inclusion=('post_inclusion_verified','mean'),
             cert_verification=('certificate_verified','mean'),
             deletion_latency_ms=('deletion_latency_ms','median')).reset_index()
        t.to_csv(tables/'T2_post_erasure.csv',index=False)
    if 'E3' in raw:
        e=raw['E3'];t=e.copy()
        t['wilson_low']=[binomtest(int(r.correct_matches),int(r.targets)).proportion_ci(method='wilson').low for r in t.itertuples()]
        t['wilson_high']=[binomtest(int(r.correct_matches),int(r.targets)).proportion_ci(method='wilson').high for r in t.itertuples()]
        t.to_csv(tables/'T3_dictionary_attack.csv',index=False)
        fig,ax=plt.subplots(figsize=(8,4.5))
        xx=np.arange(len(t));ax.bar(xx,t.linkage_rate*100)
        ax.errorbar(xx,t.linkage_rate*100,yerr=[(t.linkage_rate-t.wilson_low)*100,(t.wilson_high-t.linkage_rate)*100],
                    fmt='none',ecolor='black',capsize=4)
        ax.set_xticks(xx,t.method,rotation=15,ha='right');ax.set_ylabel('Correct matches (%)')
        ax.set_title('F1 · Offline matching with known-event candidates')
        _save(fig,figs/'F1_linkage')
    if 'E4' in raw:
        e=raw['E4']
        t=e.groupby(['timestamp','batch_size','event_category','issuer'],as_index=False).agg(
              uniqueness_rate=('uniqueness_rate','mean'),
              median_anonymity_set=('median_anonymity_set','mean'),
              under_k5_rate=('under_k5_rate','mean'),
              audit_time_precision=('audit_time_precision_rank','mean'))
        t.to_csv(tables/'T4_metadata_leakage.csv',index=False)
        fig,ax=plt.subplots(figsize=(8,5))
        markers={'exact':'o','coarse':'s','hidden':'^'}
        for cat,subset in e.groupby('event_category'):
            ax.scatter(subset.audit_time_precision_rank+np.log10(subset.batch_size)*.07,
                       subset.uniqueness_rate*100,alpha=.5,s=35,label=cat,marker=markers[cat])
        ax.set_xticks([1,2,3,4],['day','hour','minute','second']);ax.set_xlabel('Time disclosure precision')
        ax.set_ylabel('Unique visible metadata signatures (%)')
        ax.set_title('F2 · Metadata privacy–audit specificity trade-off')
        ax.legend(title='Category visibility');_save(fig,figs/'F2_metadata_tradeoff')
    if 'E5' in raw:
        e=raw['E5']
        t=e.groupby(['method','events','batch_size'],as_index=False).agg(
             throughput_median=('throughput_events_s','median'),
             proof_generation_ms=('proof_generation_ms','median'),
             proof_verification_ms=('proof_verification_ms','median'),
             proof_size_bytes=('proof_size_bytes','median'),
             encrypted_bytes=('encrypted_bytes','median'),
             anchors=('anchors','median'),
             rss_delta_mb=('rss_delta_mb','median'))
        t.to_csv(tables/'T5_performance.csv',index=False)
        fig,ax=plt.subplots(figsize=(8,4.5))
        for (method,n),sub in t.groupby(['method','events']):
            if method=='B4-offchain':continue
            ax.plot(sub.batch_size,sub.throughput_median,marker='o',label=f'{method} N={n}')
        ax.set_xscale('log');ax.set_xlabel('Batch size');ax.set_ylabel('Events / second')
        ax.set_title('F3 · Merkle batching and ingestion performance');ax.legend(fontsize=7)
        _save(fig,figs/'F3_batching')
        fig,ax=plt.subplots(figsize=(8,4.5))
        for method,sub in t.groupby('method'):
            x=sub.groupby('events').encrypted_bytes.median()
            ax.plot(x.index,x.values/1024,marker='o',label=method)
        ax.set_xlabel('Events');ax.set_ylabel('Encrypted payload (KiB)')
        ax.set_title('F4 · Retained encrypted payload volume before deletion')
        ax.legend();_save(fig,figs/'F4_storage_scaling')
        # Matched repetitions, shared generated streams, speed comparison on same n/batch.
        pairs=[]
        for (n,batch),g in e.groupby(['events','batch_size']):
            a=g[g.method=='P1-batched'].sort_values('repetition')
            b=g[g.method=='B5-per-event'].sort_values('repetition')
            if len(a)>=3 and len(a)==len(b):
                diffs=a.duration_s.to_numpy()-b.duration_s.to_numpy()
                try:pval=float(wilcoxon(diffs).pvalue)
                except ValueError:pval=None
                pairs.append({'events':int(n),'batch_size':int(batch),'paired_n':len(diffs),
                              'median_difference_s':float(np.median(diffs)),'wilcoxon_p_raw':pval})
        if pairs:
            # Holm-Bonferroni adjusted p values across planned comparisons.
            good=[i for i,p in enumerate(pairs) if p['wilcoxon_p_raw'] is not None]
            order=sorted(good,key=lambda i:pairs[i]['wilcoxon_p_raw'])
            peak=0.
            for rank,i in enumerate(order):
                peak=max(peak,(len(order)-rank)*pairs[i]['wilcoxon_p_raw'])
                pairs[i]['holm_adjusted_p']=min(1.,peak)
            pd.DataFrame(pairs).to_csv(tables/'E5_paired_statistics.csv',index=False)
            stats['E5_paired_comparisons']=pairs
    if 'E6' in raw:
        t=raw['E6']
        t.to_csv(tables/'T6_audit_queries.csv',index=False)
    if 'E7' in raw:
        raw['E7'].to_csv(tables/'E7_lifecycle.csv',index=False)
    # Workflow figure: verifiable state changes versus bounded assurance.
    fig,ax=plt.subplots(figsize=(10,3.7));ax.axis('off')
    states=[('Ingest event','AES-GCM\nOff-chain'),('Commit batch','Merkle root\nSigned anchor'),
            ('Authorized audit','Selected field\nMerkle openings'),('Erase payload','Delete local key,\nciphertext & indexes'),
            ('Post-erasure','Inclusion + signed\ndeletion certificate')]
    for i,(header,detail) in enumerate(states):
        x=(i+.5)/len(states)
        ax.text(x,.56,header+'\n'+detail,ha='center',va='center',fontsize=8,
                bbox={'boxstyle':'round,pad=.55','facecolor':'white','edgecolor':'grey'})
        if i<len(states)-1:ax.annotate('',xy=(x+.115,.55),xytext=(x+.085,.55),arrowprops={'arrowstyle':'->'})
    ax.set_title('F5 · SAL event lifecycle (signed workflow evidence, not global erasure proof)')
    _save(fig,figs/'F5_lifecycle')
    (out/'statistics.json').write_text(json.dumps(stats,indent=2))
