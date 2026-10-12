"""Cryptographic protocol, append-only simulated ledger, and off-chain storage.

Security boundary: publisher signing keys and SQLite database are local and not
an independently replicated consensus ledger. This is an evaluation prototype.
"""
from __future__ import annotations
from dataclasses import dataclass
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canon(obj: Any) -> bytes:
    def normalize(item):
        if isinstance(item, str): return unicodedata.normalize('NFC', item)
        if isinstance(item, dict): return {normalize(k): normalize(v) for k, v in item.items()}
        if isinstance(item, (tuple, list)): return [normalize(x) for x in item]
        if item is None or isinstance(item, (bool, int)): return item
        if isinstance(item, float) and math.isfinite(item): return item
        raise TypeError(f'Unsupported canonical value: {type(item).__name__}')
    return json.dumps(normalize(obj), sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(domain: str, *parts: bytes) -> bytes:
    # Unambiguous framing and domain separation. SHA-256 is not used as an authenticator.
    h = hashlib.sha256(domain.encode('ascii') + b'\x00')
    for part in parts:
        h.update(len(part).to_bytes(8, 'big'))
        h.update(part)
    return h.digest()


def field_leaf(name: str, value: Any, salt: bytes) -> bytes:
    return sha('SAL-FIELD-v1', name.encode(), salt, canon(value))


def event_commitment(event: dict, salt: bytes) -> bytes:
    return sha('SAL-EVENT-v1', salt, canon(event))


def batch_leaf(commitment: bytes, field_root: bytes) -> bytes:
    return sha('SAL-LEAF-v1', commitment, field_root)


def merkle_parent(left: bytes, right: bytes) -> bytes:
    return sha('SAL-NODE-v1', left, right)


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves: raise ValueError('Empty Merkle tree')
    level = list(leaves)
    while len(level) > 1:
        if len(level) & 1: level.append(level[-1])
        level = [merkle_parent(level[i], level[i+1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_path(leaves: list[bytes], index: int) -> list[dict]:
    if not 0 <= index < len(leaves): raise IndexError(index)
    level, path = list(leaves), []
    while len(level) > 1:
        if len(level) & 1: level.append(level[-1])
        other = index ^ 1
        path.append({'hash': level[other].hex(), 'left': bool(other < index)})
        level = [merkle_parent(level[i], level[i+1]) for i in range(0,len(level),2)]
        index //= 2
    return path


def verify_merkle(leaf: bytes, path: list[dict], root: bytes) -> bool:
    try:
        node = leaf
        for step in path:
            sibling = bytes.fromhex(step['hash'])
            if len(sibling) != 32 or type(step['left']) is not bool: return False
            node = merkle_parent(sibling, node) if step['left'] else merkle_parent(node, sibling)
        return secrets.compare_digest(node, root)
    except (ValueError, TypeError, KeyError):
        return False


def stable_seed(master: int, *parts: Any) -> int:
    return int.from_bytes(sha('SAL-SEED-v1', canon([master, *parts]))[:8], 'big')


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class SAL:
    """Persistent single-publisher simulation; deletion certs are ledger-signed."""
    def __init__(self, database: str | Path = ':memory:', key: Ed25519PrivateKey | None = None, batch_size=100):
        self.db = sqlite3.connect(str(database))
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA secure_delete=ON')
        self.db.execute('PRAGMA foreign_keys=ON')
        self.key = key or Ed25519PrivateKey.generate()
        self._wrapping_key = AESGCM.generate_key(bit_length=256)
        self.public_key = self.key.public_key()
        self.batch_size = batch_size
        self._pending = []
        self._initialize()

    def _initialize(self):
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS records (
          id TEXT PRIMARY KEY, commitment TEXT NOT NULL, field_root TEXT NOT NULL,
          event_salt BLOB, field_salts TEXT, ciphertext BLOB, nonce BLOB, wrapped_key BLOB,
          subject_index TEXT, policy TEXT NOT NULL, batch_seq INTEGER, proof TEXT,
          deleted INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS anchors (
          seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
          previous TEXT NOT NULL, digest TEXT NOT NULL, signature TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS deletion (
          id TEXT PRIMARY KEY, cert TEXT NOT NULL, anchor_seq INTEGER NOT NULL);
        ''')

    def issuer_public_hex(self):
        return self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def _append(self, kind: str, payload: dict):
        prior = self.db.execute('SELECT seq, digest FROM anchors ORDER BY seq DESC LIMIT 1').fetchone()
        seq = prior['seq'] + 1 if prior else 1
        previous = prior['digest'] if prior else '0'*64
        body = {'seq': seq, 'kind': kind, 'payload': payload, 'previous': previous}
        digest = sha('SAL-ANCHOR-v1', canon(body))
        signature = self.key.sign(digest)
        self.db.execute('INSERT INTO anchors VALUES (?,?,?,?,?,?)',
                        (seq, kind, canon(payload).decode(), previous, digest.hex(), signature.hex()))
        return {**body, 'digest': digest.hex(), 'signature': signature.hex()}

    def anchors(self):
        data = self.db.execute('SELECT * FROM anchors ORDER BY seq').fetchall()
        return [dict(seq=r['seq'], kind=r['kind'], payload=json.loads(r['payload']),
                     previous=r['previous'], digest=r['digest'], signature=r['signature']) for r in data]

    @staticmethod
    def verify_chain(anchors: list[dict], public_key_hex: str) -> bool:
        try:
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            prev = '0'*64
            for seq, a in enumerate(anchors, start=1):
                if a['seq'] != seq or a['previous'] != prev: return False
                body = {k: a[k] for k in ('seq','kind','payload','previous')}
                expected = sha('SAL-ANCHOR-v1', canon(body))
                if not secrets.compare_digest(expected.hex(), a['digest']): return False
                public.verify(bytes.fromhex(a['signature']), expected)
                prev = a['digest']
            return bool(anchors)
        except (ValueError, TypeError, KeyError, Exception) as exc:
            # Includes cryptography.exceptions.InvalidSignature.
            return False

    def ingest(self, event: dict, policy='policy-v1') -> str:
        if not isinstance(event, dict) or not event: raise ValueError('Event must be a non-empty dict')
        if 'subject_id' not in event: raise ValueError('Missing subject_id')
        event = json.loads(canon(event))
        record_id = str(uuid.uuid4())
        salt, data_key, nonce = secrets.token_bytes(32), AESGCM.generate_key(bit_length=256), secrets.token_bytes(12)
        field_salts = {k: secrets.token_bytes(32).hex() for k in event}
        leaves = [field_leaf(k,event[k],bytes.fromhex(field_salts[k])) for k in sorted(event)]
        field_root = merkle_root(leaves)
        commitment = event_commitment(event, salt)
        ciphertext = AESGCM(data_key).encrypt(nonce, canon(event), canon({'policy':policy,'v':'1'}))
        wrap_nonce=secrets.token_bytes(12)
        wrapped_key=wrap_nonce+AESGCM(self._wrapping_key).encrypt(wrap_nonce,data_key,record_id.encode())
        self.db.execute('''INSERT INTO records
        (id,commitment,field_root,event_salt,field_salts,ciphertext,nonce,wrapped_key,subject_index,policy)
        VALUES(?,?,?,?,?,?,?,?,?,?)''',
        (record_id,commitment.hex(),field_root.hex(),salt,json.dumps(field_salts),ciphertext,
         nonce,wrapped_key,str(event['subject_id']),policy))
        self._pending.append(record_id)
        if len(self._pending) >= self.batch_size: self.seal()
        self.db.commit()
        return record_id

    def seal(self):
        if not self._pending: return None
        rows = [self.db.execute('SELECT * FROM records WHERE id=?',(rid,)).fetchone() for rid in self._pending]
        leaves = [batch_leaf(bytes.fromhex(r['commitment']),bytes.fromhex(r['field_root'])) for r in rows]
        root = merkle_root(leaves)
        anchor = self._append('batch', {'root':root.hex(),'count':len(rows),'policy':'policy-v1',
                                        'window':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:00Z')})
        for i, r in enumerate(rows):
            self.db.execute('UPDATE records SET batch_seq=?, proof=? WHERE id=?',
                            (anchor['seq'],json.dumps(merkle_path(leaves,i)),r['id']))
        self._pending.clear()
        self.db.commit()
        return anchor

    def _get(self, record_id):
        row = self.db.execute('SELECT * FROM records WHERE id=?',(record_id,)).fetchone()
        if row is None: raise KeyError(record_id)
        return row

    def _unwrap_key(self, record_id: str, wrapped: bytes) -> bytes:
        return AESGCM(self._wrapping_key).decrypt(wrapped[:12],wrapped[12:],record_id.encode())

    def recover(self, record_id, authorized=True):
        if not authorized: raise PermissionError('Audit access denied')
        r = self._get(record_id)
        if r['deleted'] or r['ciphertext'] is None or r['wrapped_key'] is None: return None
        data = AESGCM(self._unwrap_key(record_id,r['wrapped_key'])).decrypt(r['nonce'],r['ciphertext'],canon({'policy':r['policy'],'v':'1'}))
        event = json.loads(data)
        if event_commitment(event,r['event_salt']).hex()!=r['commitment']:
            raise ValueError('Recovered event does not match commitment')
        return event

    def proof(self, record_id, disclosed_fields: list[str] | None = None, authorized=True):
        if not authorized: raise PermissionError('Audit proof access denied')
        self.seal()
        r = self._get(record_id)
        anchors = self.anchors()
        obj = {'record_id':record_id,'commitment':r['commitment'],'field_root':r['field_root'],
               'batch_seq':r['batch_seq'],'batch_path':json.loads(r['proof']), 'anchors':anchors}
        if not r['deleted']:
            event=self.recover(record_id)
            salt_dict=json.loads(r['field_salts'])
            keys=sorted(event)
            leaves=[field_leaf(k,event[k],bytes.fromhex(salt_dict[k])) for k in keys]
            if disclosed_fields is None:
                disclosed_fields=keys
                obj['event_salt']=r['event_salt'].hex()
            if any(k not in event for k in disclosed_fields): raise KeyError('Missing requested field')
            obj['fields']={k:{'value':event[k],'salt':salt_dict[k],
                              'path':merkle_path(leaves,keys.index(k))} for k in disclosed_fields}
        return obj

    @staticmethod
    def verify_proof(proof: dict, public_key_hex: str, require_full=False) -> bool:
        try:
            anchors=proof['anchors']
            if not SAL.verify_chain(anchors,public_key_hex): return False
            anchor=anchors[proof['batch_seq']-1]
            if anchor['kind']!='batch': return False
            commitment=bytes.fromhex(proof['commitment']); root=bytes.fromhex(proof['field_root'])
            if not verify_merkle(batch_leaf(commitment,root),proof['batch_path'],
                                 bytes.fromhex(anchor['payload']['root'])): return False
            for name, disclosed in proof.get('fields',{}).items():
                leaf=field_leaf(name,disclosed['value'],bytes.fromhex(disclosed['salt']))
                if not verify_merkle(leaf,disclosed['path'],root):return False
            if require_full:
                if 'event_salt' not in proof or 'fields' not in proof: return False
                fields=proof['fields']; event={k:v['value'] for k,v in fields.items()}
                if event_commitment(event,bytes.fromhex(proof['event_salt']))!=commitment: return False
                if merkle_root([field_leaf(k,event[k],bytes.fromhex(fields[k]['salt'])) for k in sorted(event)])!=root:
                    return False
            return True
        except (ValueError,KeyError,TypeError,IndexError,Exception): return False

    def delete(self, record_id: str, approved=False, request='approved-erasure', policy='policy-v1') -> dict:
        if not approved: raise PermissionError('Deletion requires authorization')
        self.seal()
        r = self._get(record_id)
        if r['deleted']: raise ValueError('Record already deleted')
        request_hash=sha('SAL-ERASURE-REQUEST-v1',secrets.token_bytes(32),canon(request)).hex()
        window=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:00Z')
        body={'commitment':r['commitment'],'request_digest':request_hash,'deletion_window':window,
              'policy':policy,'record_ref':sha('SAL-REFERENCE-v1',bytes.fromhex(r['commitment'])).hex()}
        body['digest']=sha('SAL-DELETION-v1',canon(body)).hex()
        # Transactional deletion + certificate append within a single SQLite DB.
        with self.db:
            self.db.execute('''UPDATE records SET ciphertext=NULL, wrapped_key=NULL, nonce=NULL,
                event_salt=NULL, field_salts=NULL, subject_index=NULL, deleted=1 WHERE id=?''',(record_id,))
            anchor=self._append('deletion',body)
            self.db.execute('INSERT INTO deletion VALUES (?,?,?)',
                            (record_id,canon(body).decode(),anchor['seq']))
        return {'certificate':body,'anchor_seq':anchor['seq']}

    def verify_deletion(self, record_id: str, proof: dict | None = None) -> bool:
        if proof is None: proof=self.proof(record_id)
        try:
            r=self.db.execute('SELECT cert,anchor_seq FROM deletion WHERE id=?',(record_id,)).fetchone()
            if r is None: return False
            cert=json.loads(r['cert']); digest=cert.pop('digest')
            if sha('SAL-DELETION-v1',canon(cert)).hex()!=digest: return False
            cert['digest']=digest
            if cert['commitment']!=proof['commitment']: return False
            a=proof['anchors'][r['anchor_seq']-1]
            return a['kind']=='deletion' and a['payload']==cert and self.verify_proof(proof,self.issuer_public_hex())
        except (ValueError,KeyError,IndexError,TypeError): return False

    @staticmethod
    def verify_post(proof: dict, certificate: dict, public_key_hex: str) -> bool:
        try:
            if not SAL.verify_proof(proof,public_key_hex):return False
            cert=copy.deepcopy(certificate)
            digest=cert.pop('digest')
            if sha('SAL-DELETION-v1',canon(cert)).hex()!=digest: return False
            cert['digest']=digest
            if cert['commitment']!=proof['commitment']: return False
            a=next((a for a in proof['anchors'] if a['kind']=='deletion' and a['payload']==cert),None)
            return a is not None and a['seq']>proof['batch_seq']
        except (KeyError,ValueError,TypeError):return False

    def deletion_certificate(self, record_id):
        row=self.db.execute('SELECT cert FROM deletion WHERE id=?',(record_id,)).fetchone()
        return json.loads(row['cert']) if row else None

    def close(self):
        self.db.close()
