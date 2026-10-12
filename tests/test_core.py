import copy
import json
import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from sal.core import SAL, canon, sha, merkle_root, merkle_path, verify_merkle, event_commitment

EVENT={'subject_id':'USER-0001','action':'read','resource_id':'file-A','timestamp_exact':'2026-01-01T00:00:00Z'}

class CoreTests(unittest.TestCase):
    def test_canonicalization(self):
        self.assertEqual(canon({'é':1,'a':'z'}),canon({'a':'z','e\u0301':1}))
        with self.assertRaises(TypeError):canon({'bad':object()})
        self.assertNotEqual(sha('A',b'x'),sha('B',b'x'))
        self.assertNotEqual(sha('A',b'a',b'bc'),sha('A',b'ab',b'c'))

    def test_merkle_odd_and_single(self):
        for size in [1,2,3,5,17,32]:
            leaves=[sha('leaf',bytes([i])) for i in range(size)]
            root=merkle_root(leaves)
            for i,leaf in enumerate(leaves):
                path=merkle_path(leaves,i)
                self.assertTrue(verify_merkle(leaf,path,root))
                if path:
                    broken=copy.deepcopy(path);broken[0]['hash']='ff'*32
                    self.assertFalse(verify_merkle(leaf,broken,root))
        with self.assertRaises(ValueError):merkle_root([])

    def test_selective_disclosure_and_erasure(self):
        store=SAL(batch_size=2)
        rid=store.ingest(EVENT)
        store.ingest({**EVENT,'subject_id':'USER-0002'})
        pub=store.issuer_public_hex()
        subset=store.proof(rid,['action'])
        self.assertTrue(SAL.verify_proof(subset,pub))
        self.assertFalse(SAL.verify_proof(subset,pub,require_full=True))
        self.assertEqual(subset['fields']['action']['value'],'read')
        self.assertNotIn('subject_id',subset['fields'])
        full=store.proof(rid)
        self.assertTrue(SAL.verify_proof(full,pub,require_full=True))
        self.assertEqual(store.recover(rid),EVENT)
        with self.assertRaises(PermissionError):store.recover(rid,authorized=False)
        with self.assertRaises(PermissionError):store.delete(rid,approved=False)
        result=store.delete(rid,approved=True)
        post=store.proof(rid)
        self.assertIsNone(store.recover(rid))
        self.assertNotIn('fields',post)
        self.assertTrue(SAL.verify_post(post,result['certificate'],pub))
        self.assertTrue(store.verify_deletion(rid))
        self.assertIsNone(store._get(rid)['wrapped_key'])
        self.assertIsNone(store._get(rid)['ciphertext'])
        self.assertIsNone(store._get(rid)['subject_index'])
        with self.assertRaises(ValueError):store.delete(rid,approved=True)
        altered=copy.deepcopy(result['certificate']);altered['policy']='forged'
        self.assertFalse(SAL.verify_post(post,altered,pub))
        store.close()

    def test_anchor_tampering(self):
        s=SAL(batch_size=1)
        ids=[s.ingest({**EVENT,'subject_id':str(i)}) for i in range(4)]
        proof=s.proof(ids[-1]);pub=s.issuer_public_hex()
        self.assertTrue(SAL.verify_proof(proof,pub))
        for kind in ['swap','sig','digest','previous']:
            forged=copy.deepcopy(proof)
            if kind=='swap':forged['anchors'][1],forged['anchors'][2]=forged['anchors'][2],forged['anchors'][1]
            if kind=='sig':forged['anchors'][0]['signature']='00'*64
            if kind=='digest':forged['anchors'][0]['digest']='00'*32
            if kind=='previous':forged['anchors'][1]['previous']='00'*32
            self.assertFalse(SAL.verify_proof(forged,pub),kind)
        other=SAL();self.assertFalse(SAL.verify_proof(proof,other.issuer_public_hex()))
        s.close();other.close()

if __name__=='__main__':unittest.main()
