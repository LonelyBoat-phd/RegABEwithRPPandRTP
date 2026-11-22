from functools import cached_property
"""Reference implementation of RegABE algorithms and performance benchmarks.
All timing entrypoints receive only the material their role consumes.
"""
from dataclasses import dataclass, replace
from typing import Any
from collections import defaultdict,OrderedDict
from copy import deepcopy
import secrets
import threading
from functools import lru_cache
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from . import primitives as a
from .metrics import stage
from .policy import Policy,reconstruct

class ProtocolError(a.RegABEError): pass


def check(ok,message):
    if not ok: raise ProtocolError(message)


def verify(key,signature,message):
    try: Ed25519PublicKey.from_public_bytes(key).verify(signature,message)
    except (InvalidSignature,ValueError,TypeError) as exc: raise a.AuthorizationFailure('signature') from exc


def seq(parts):
    items=tuple(parts)
    return a.i2b(len(items),4)+b''.join(a.i2b(len(p),4)+p for p in items)


@lru_cache(maxsize=2048)
def encoded_fields(parts):
    return seq(parts)


@dataclass(frozen=True)
class Meta:
    pp: bytes
    sid: bytes
    ctx: bytes
    L: int
    u: int
    @cached_property
    def _wire(self): return encoded_fields((self.pp,self.sid,self.ctx,a.i2b(self.L,4),a.i2b(self.u,4)))
    def wire(self):return self._wire


@dataclass(frozen=True)
class Path:
    index: int
    count: int
    siblings: tuple


@dataclass(frozen=True)
class TreeNode:
    digest: bytes
    left: Any=None
    right: Any=None


class Tree:
    """Persistent Merkle nodes: updating a leaf shares unchanged subtrees."""
    def __init__(self,domain,leaves):
        self.domain=domain;self.count=len(leaves)
        check(self.count>0,'empty tree')
        size=1<<(self.count-1).bit_length()
        bottom=[TreeNode(a.sha256(b'LEAF',domain,a.i2b(i,4),x)) for i,x in enumerate(leaves)]
        bottom += [TreeNode(a.sha256(b'EMPTY',domain,a.i2b(i,4))) for i in range(self.count,size)]
        level=0
        while len(bottom)>1:
            bottom=[TreeNode(a.sha256(b'NODE',domain,a.i2b(level,4),bottom[i].digest,bottom[i+1].digest),bottom[i],bottom[i+1]) for i in range(0,len(bottom),2)]
            level+=1
        self._node=bottom[0]
    @property
    def root(self):return self._node.digest
    def updated(self,index,leaf):
        check(type(index)==int and 0<=index<self.count,'tree update index')
        digest=a.sha256(b'LEAF',self.domain,a.i2b(index,4),leaf)
        def update(node,height):
            if height==0:return TreeNode(digest)
            if (index>>(height-1))&1:left,right=node.left,update(node.right,height-1)
            else:left,right=update(node.left,height-1),node.right
            return TreeNode(a.sha256(b'NODE',self.domain,a.i2b(height-1,4),left.digest,right.digest),left,right)
        tree=object.__new__(Tree);tree.domain=self.domain;tree.count=self.count
        tree._node=update(self._node,(self.count-1).bit_length())
        return tree
    def path(self,index):
        check(type(index)==int and 0<=index<self.count,'tree index')
        node=self._node;siblings=[]
        for height in range((self.count-1).bit_length(),0,-1):
            if (index>>(height-1))&1:siblings.append(node.left.digest);node=node.right
            else:siblings.append(node.right.digest);node=node.left
        return Path(index,self.count,tuple(reversed(siblings)))


def path_root(domain,leaf,path):
    check(type(path.index)==int and type(path.count)==int and 0<=path.index<path.count,'proof index/count')
    depth=(path.count-1).bit_length()
    check(len(path.siblings)==depth,'proof length')
    h=a.sha256(b'LEAF',domain,a.i2b(path.index,4),leaf);idx=path.index
    for level,sibling in enumerate(path.siblings):
        check(isinstance(sibling,bytes) and len(sibling)==32,'proof hash')
        left,right=(sibling,h) if idx&1 else (h,sibling)
        h=a.sha256(b'NODE',domain,a.i2b(level,4),left,right);idx//=2
    return h


def verify_path(domain,leaf,path,root):
    check(path_root(domain,leaf,path)==root,'Merkle root')


def domain(meta,kind,*indices): return a.sha256(b'TREE',meta.wire(),kind,*[a.i2b(i,4) for i in indices])
def helper_leaf(i,w,point): return seq([a.i2b(i,4),a.i2b(w,4),a.pbytes_g2(point)])


@dataclass(frozen=True)
class Descriptor:
    attr: int
    counter: int
    U: Any
    helper_root: bytes
    @cached_property
    def _wire(self):return seq([a.i2b(self.attr,4),a.i2b(self.counter,8),a.pbytes_g1(self.U),self.helper_root])
    def wire(self):return self._wire


@dataclass(frozen=True)
class Block:
    descriptor: Descriptor
    helpers: tuple
    tree: Any


def make_block(meta,w,counter,U,helpers):
    helpers=tuple(helpers)
    check(len(helpers)==meta.L,'helper shape')
    tree=Tree(domain(meta,b'HELPER',w),[helper_leaf(i,w,x) for i,x in enumerate(helpers)])
    return Block(Descriptor(w,counter,U,tree.root),helpers,tree)


@dataclass(frozen=True)
class State:
    blocks: tuple
    tree: Any


def make_state(meta,blocks):
    blocks=tuple(blocks)
    check(len(blocks)==meta.u and all(b.descriptor.attr==w for w,b in enumerate(blocks)),'state shape')
    return State(blocks,Tree(domain(meta,b'ATTR'),[b.descriptor.wire() for b in blocks]))


def replace_block(meta,state,w,block):
    check(block.descriptor.attr==w,'updated attribute')
    blocks=list(state.blocks);blocks[w]=block
    return State(tuple(blocks),state.tree.updated(w,block.descriptor.wire()))


@dataclass(frozen=True)
class Head:
    meta: Meta
    version: int
    parent: bytes
    base: bytes
    root: bytes
    event: bytes
    manifest: bytes
    @cached_property
    def _wire(self):return encoded_fields((b'REGABE-EFFICIENCY-v2',self.meta.wire(),a.i2b(self.version,8),self.parent,self.base,self.root,self.event,self.manifest))
    @cached_property
    def digest(self):return a.sha256(b'HEAD',self.wire())
    def wire(self):return self._wire


@dataclass(frozen=True)
class Auth:
    ra: bytes
    kc: bytes
    board: bytes


@dataclass(frozen=True)
class Trust:
    ra: bytes
    kc: bytes
    board: bytes


def authenticate(head,auth,trust):
    message=head.wire()
    for key,signature in [(trust.ra,auth.ra),(trust.kc,auth.kc),(trust.board,auth.board)]:verify(key,signature,message)


@dataclass(frozen=True)
class Commitment:
    head: Head
    auth: Auth


class Board:
    """Public commit chain only: no RA signing key, user keys, masks or bits."""
    def __init__(self,meta,ra_key,kc_key):
        self.meta=meta;self._signer=Ed25519PrivateKey.generate()
        self.trust=Trust(ra_key,kc_key,self._signer.public_key().public_bytes_raw())
        self._commits={};self._latest=None;self._lock=threading.RLock()
    @property
    def latest(self):return deepcopy(self._latest)
    def append(self,head,ra_sig,kc_sig):
        with self._lock:
            check(head.meta==self.meta,'Board context')
            verify(self.trust.ra,ra_sig,head.wire());verify(self.trust.kc,kc_sig,head.wire())
            if head.digest in self._commits:return deepcopy(self._commits[head.digest])
            if self._latest is None:check(head.version==0 and head.parent==b'\0'*32,'genesis')
            else:check(head.version==self._latest.head.version+1 and head.parent==self._latest.head.digest,'CAS parent')
            receipt=Commitment(deepcopy(head),Auth(bytes(ra_sig),bytes(kc_sig),self._signer.sign(head.wire())))
            self._commits[head.digest]=receipt;self._latest=receipt
            return deepcopy(receipt)
    def resolve(self,digest):
        check(digest in self._commits,'uncommitted head')
        return deepcopy(self._commits[digest])


@dataclass(frozen=True)
class Event:
    meta: Meta
    attr: int
    parent: bytes
    old_version: int
    new_version: int
    old_counter: int
    new_counter: int
    nonce: bytes
    @cached_property
    def _wire(self):return seq([self.meta.wire(),a.i2b(self.attr,4),self.parent,a.i2b(self.old_version,8),a.i2b(self.new_version,8),a.i2b(self.old_counter,8),a.i2b(self.new_counter,8),self.nonce])
    @cached_property
    def digest(self):return a.sha256(b'EVT',self.wire())
    def wire(self):return self._wire


def derive_key(root,meta,i):
    return a.hmac.new(root,seq([b'REGABE-UPD-KEY',meta.wire(),a.i2b(i,4)]),a.hashlib.sha512).digest()[:32]


def correction(key,meta,i,event):
    return int.from_bytes(a.hmac.new(key,seq([b'REGABE-UPD-CHI',meta.wire(),a.i2b(i,4),event.wire()]),a.hashlib.sha512).digest(),'big')%a.P


@dataclass(frozen=True)
class Manifest:
    event: Event
    delta_root: bytes
    old_descriptor: bytes
    new_descriptor: bytes
    vector_digest: bytes
    @cached_property
    def _wire(self):return seq([self.event.wire(),self.delta_root,self.old_descriptor,self.new_descriptor,self.vector_digest])
    @cached_property
    def digest(self):return a.sha256(b'RVMAN',self.wire())
    def wire(self):return self._wire


def delta_domain(event):return a.sha256(b'DELTA',event.meta.wire(),event.digest)
def delta_leaf(event,index,point):return seq([event.digest,a.i2b(event.attr,4),a.i2b(index,4),b'G1' if index==0 else b'G2',a.pbytes_g1(point) if index==0 else a.pbytes_g2(point)])
def delta_payload(event,du,dw):return (delta_leaf(event,0,du),)+tuple(delta_leaf(event,i+1,x) for i,x in enumerate(dw))


@dataclass(frozen=True)
class Update:
    manifest: Manifest
    du: Any
    dw: tuple
    head: Head
    ra_signature: bytes
    def canonical(self):return seq([self.manifest.wire(),seq(delta_payload(self.manifest.event,self.du,self.dw)),self.head.wire(),self.ra_signature])


@dataclass(frozen=True)
class Prepared:
    token: bytes


@dataclass(frozen=True)
class PublicParameters:
    meta: Meta
    g: Any
    h: Any
    omega: Any
    T: Any
    fixed_root: bytes


@dataclass(frozen=True)
class UserPublic:
    slot: int
    A: Any
    B: Any
    V: Any
    U: Any
    path: Path


def fixed_leaf(u):return seq([a.i2b(u.slot,4),a.pbytes_g2(u.A),a.pbytes_g2(u.B),a.pbytes_g2(u.V),a.pbytes_g1(u.U)])
def base_digest(pp):return a.sha256(b'BASE',pp.meta.wire(),a.pbytes_g1(pp.g),a.pbytes_g1(pp.h),a.gt_bytes(pp.omega),a.pbytes_g1(pp.T),pp.fixed_root)


@dataclass(frozen=True)
class Cell:
    descriptor: Descriptor
    path: Path


@dataclass(frozen=True)
class SenderInput:
    public: PublicParameters
    commit: Commitment
    cells: tuple
    historical: bool


@dataclass(frozen=True)
class UserCell:
    cell: Cell
    helper: Any
    path: Path


@dataclass(frozen=True)
class DecryptInput:
    public: PublicParameters
    fixed: UserPublic
    commit: Commitment
    cells: tuple


@dataclass(frozen=True)
class SyncInput:
    manifest: Manifest
    commit: Commitment
    du: Any
    own_delta: Any
    common_path: Path
    own_path: Path


class RA:
    """Private statuses and correction keys; no initial xi or source secrets."""
    def __init__(self,sp,profiles,*,fixed_base=True):
        check(type(fixed_base)==bool,'fixed_base must be bool')
        self.meta=Meta(sp.ctx.pp_id,sp.ctx.sid,sp.ctx.ctx_id,sp.ctx.L,sp.ctx.u)
        self.g,self.A,self.U,self.W=deepcopy((sp.g1,tuple(sp.A),tuple(sp.U),sp.W))
        check(len(profiles)==self.meta.L and all(len(row)==self.meta.u and all(x in (0,1) for x in row) for row in profiles),'profile shape')
        self._bits=[list(row) for row in profiles];self._root=secrets.token_bytes(32)
        self._keys=tuple(derive_key(self._root,self.meta,i) for i in range(self.meta.L))
        self._signer=Ed25519PrivateKey.generate();self.verification_key=self._signer.public_key().public_bytes_raw()
        self._nonces=set();self._pending={};self._head=None
        self._use_fixed_base=fixed_base
        self._correction_precompute=None
        # Public-base precomputation is charged to RA initialization. No event
        # scalar or correction is cached; all HMACs remain per-event.
        self._correction_tables()
    def _correction_tables(self):
        if not self._use_fixed_base:return None
        # Snapshot ALL coordinates, not only compressed x/sign encodings:
        # off-curve points can share a compressed encoding with a valid point.
        # Integer tuples also detect in-place mutation of field objects.
        key=(a.pbytes_g1(self.g),tuple(a.pbytes_g2(x) for x in self.A))
        cached=self._correction_precompute
        if cached is None or cached[0]!=key:
            cached=(key,(a._FixedBaseTable(self.g,'G1'),
                         tuple(a._FixedBaseTable(x,'G2') for x in self.A)))
            self._correction_precompute=cached
        return cached[1]
    def deliver_own_key(self,slot):
        check(0<=slot<self.meta.L,'key recipient')
        return self._keys[slot] # driver models confidential delivery; never Board/KC
    def endorse_genesis(self,head):
        check(self._head is None and head.meta==self.meta and head.version==0,'RA genesis')
        self._head=head.digest;return self._signer.sign(head.wire())
    def prepare(self,parent,block,target,attr,nonce=None,*,metrics=None):
        with stage(metrics, 'ra_checks_s'):
            check(parent.meta==self.meta and parent.digest==self._head,'RA stale parent')
            check(0<=target<self.meta.L and 0<=attr<self.meta.u,'revocation coordinate')
            nonce=secrets.token_bytes(64) if nonce is None else nonce
            check(isinstance(nonce,bytes) and len(nonce)==64 and nonce not in self._nonces,'nonce replay/width')
            self._nonces.add(nonce)
            check(self._bits[target][attr]==0 and block.descriptor.attr==attr,'already revoked/attribute')
            counter=block.descriptor.counter
            evt=Event(self.meta,attr,parent.digest,parent.version,parent.version+1,counter,counter+1,nonce)
        with stage(metrics, 'ra_prf_s'):
            chis=[correction(k,self.meta,i,evt) for i,k in enumerate(self._keys)];lam=sum(chis)%a.P
        with stage(metrics, 'ra_precompute_lookup_s'):
            tables=self._correction_tables()
        with stage(metrics, 'ra_corrections_s'):
            common=a.g1_pow(self.g,lam) if tables is None else tables[0].multiply(lam)
            du=a.g1_prod([common,self.U[target]])
            dw=tuple(a.g2_prod([
                a.g2_pow(self.A[i],lam-chis[i]) if tables is None else tables[1][i].multiply(lam-chis[i])
                ]+([] if i==target else [self.W[i,target]])) for i in range(self.meta.L))
        with stage(metrics, 'ra_successor_arithmetic_s'):
            next_u=a.g1_prod([block.descriptor.U,du])
            next_helpers=[a.g2_prod([x,y]) for x,y in zip(block.helpers,dw)]
        with stage(metrics, 'ra_helper_tree_s'):
            nb=make_block(self.meta,attr,counter+1,next_u,next_helpers)
        with stage(metrics, 'ra_delta_auth_s'):
            leaves=delta_payload(evt,du,dw);tree=Tree(delta_domain(evt),leaves)
            manifest=Manifest(evt,tree.root,block.descriptor.wire(),nb.descriptor.wire(),a.sha256(b'VECTOR',seq(leaves)))
        # The KC supplies the outer root after complete NextState. RA independently
        # checks that root using the old authenticated attribute path in finalize.
        with stage(metrics, 'ra_pending_copy_s'):
            self._pending[manifest.digest]=(target,manifest,du,dw,nb)
            return deepcopy((manifest,du,dw,nb))
    def finalize(self,parent,old_cell,manifest,du,dw,new_block,*,metrics=None):
        with stage(metrics, 'ra_finalize_checks_s'):
            entry=self._pending.get(manifest.digest);check(entry is not None,'unknown RA proposal')
            _,stored,sdu,sdw,snb=entry
            check(manifest==stored and seq(delta_payload(manifest.event,du,dw))==seq(delta_payload(stored.event,sdu,sdw)),'RA proposal bytes')
            check(parent.digest==self._head and old_cell.descriptor.wire()==manifest.old_descriptor,'RA source state')
            validate_cell(self.meta,parent,old_cell)
        with stage(metrics, 'ra_head_auth_s'):
            root=path_root(domain(self.meta,b'ATTR'),manifest.new_descriptor,old_cell.path)
            head=Head(self.meta,parent.version+1,parent.digest,parent.base,root,manifest.event.digest,manifest.digest)
            return Update(manifest,deepcopy(sdu),deepcopy(sdw),head,self._signer.sign(head.wire()))
    def accept_commit(self,commit,trust):
        authenticate(commit.head,commit.auth,trust)
        check(commit.head.parent==self._head,'RA committed parent')
        entry=self._pending.get(commit.head.manifest);check(entry is not None,'RA pending manifest')
        target,manifest,_,_,_=entry
        check(commit.head.event==manifest.event.digest,'RA committed event')
        self._bits[target][manifest.event.attr]=1;self._head=commit.head.digest
        self._pending.clear()


class KC:
    """Public material store + checked-state service. No user/RA secrets."""
    def __init__(self,meta,public,state,fixed,ra_key):
        self.meta=meta;self.public=deepcopy(public);self._state=deepcopy(state);self._fixed=deepcopy(fixed)
        self._signer=Ed25519PrivateKey.generate();self.verification_key=self._signer.public_key().public_bytes_raw()
        self.ra_key=ra_key;self._head=None;self._history={};self._prepared={};self._sync={}
        self.validation_builds=0
    def genesis(self,ra,board):
        check(self._head is None,'KC already initialized')
        head=Head(self.meta,0,b'\0'*32,base_digest(self.public),self._state.tree.root,b'INIT',b'INIT')
        receipt=board.append(head,ra.endorse_genesis(head),self._signer.sign(head.wire()))
        self._head=head;self._history[head.digest]=self._state
        return receipt
    @property
    def head(self):return deepcopy(self._head)
    def revocation_material(self,attr):return deepcopy((self._head,self._state.blocks[attr]))
    def prepare_with(self,ra,target,attr,*,metrics=None):
        with stage(metrics, 'proposal_material_s'):
            parent,block=self.revocation_material(attr)
        proposal=ra.prepare(parent,block,target,attr,metrics=metrics)
        with stage(metrics, 'proposal_path_s'):
            cell=Cell(block.descriptor,self._state.tree.path(attr))
        return ra.finalize(parent,cell,*proposal,metrics=metrics)
    def validate(self,packet,*,metrics=None):
        with stage(metrics, 'kc_snapshot_s'):
            packet=deepcopy(packet) # validation pins an owned snapshot, never caller aliases
            evt=packet.manifest.event;head=packet.head;old=self._head
        with stage(metrics, 'kc_signature_s'):
            verify(self.ra_key,packet.ra_signature,head.wire())
        with stage(metrics, 'kc_checks_s'):
            check(evt.meta==self.meta and head.meta==self.meta,'update context')
            check(evt.parent==old.digest==head.parent and evt.old_version==old.version and evt.new_version==head.version==old.version+1,'update parent/version')
            check(0<=evt.attr<self.meta.u and len(packet.dw)==self.meta.L,'update shape')
            check(isinstance(evt.nonce,bytes) and len(evt.nonce)==64,'update nonce')
            block=self._state.blocks[evt.attr]
            check(evt.old_counter==block.descriptor.counter and evt.new_counter==evt.old_counter+1,'update counter')
        with stage(metrics, 'kc_membership_s'):
            a.member_many((packet.du, *packet.dw))
        with stage(metrics, 'kc_vector_auth_s'):
            leaves=delta_payload(evt,packet.du,packet.dw);tree=Tree(delta_domain(evt),leaves)
            check(tree.root==packet.manifest.delta_root and a.sha256(b'VECTOR',seq(leaves))==packet.manifest.vector_digest,'delta commitment')
        with stage(metrics, 'kc_successor_arithmetic_s'):
            next_u=a.g1_prod([block.descriptor.U,packet.du])
            next_helpers=[a.g2_prod([x,y]) for x,y in zip(block.helpers,packet.dw)]
        with stage(metrics, 'kc_helper_tree_s'):
            nb=make_block(self.meta,evt.attr,evt.new_counter,next_u,next_helpers)
        with stage(metrics, 'kc_descriptor_checks_s'):
            check(block.descriptor.wire()==packet.manifest.old_descriptor and nb.descriptor.wire()==packet.manifest.new_descriptor,'descriptor transition')
        with stage(metrics, 'kc_attribute_state_s'):
            state=replace_block(self.meta,self._state,evt.attr,nb)
        with stage(metrics, 'kc_head_checks_s'):
            check(head.root==state.tree.root and head.base==old.base and head.event==evt.digest and head.manifest==packet.manifest.digest,'head commitments')
        with stage(metrics, 'kc_sign_stage_s'):
            token=secrets.token_bytes(32)
            self._prepared[token]=(old.digest,packet,state,tree,self._signer.sign(head.wire()))
            self.validation_builds+=1
            return Prepared(token)
    def commit(self,board,prepared):
        # Commit reuses only KC-owned, already checked state; no caller-supplied
        # candidate state or mutable packet can be substituted after validation.
        check(isinstance(prepared,Prepared) and prepared.token in self._prepared,'unknown validation receipt')
        parent,packet,state,tree,sig=self._prepared[prepared.token]
        check(parent==self._head.digest and board.latest.head.digest==parent,'commit CAS')
        receipt=board.append(packet.head,packet.ra_signature,sig)
        self._state=state;self._head=packet.head;self._history[self._head.digest]=state
        self._sync[self._head.digest]=(packet.manifest,packet.du,packet.dw,tree,receipt)
        self._prepared.clear() # other candidates name the now-stale parent
        return receipt
    def sender_input(self,board,labels,head_digest=None,historical=False):
        receipt=board.latest if head_digest is None else board.resolve(head_digest)
        check(historical or receipt.head.digest==board.latest.head.digest,'explicit historical encryption required')
        state=self._history.get(receipt.head.digest);check(state is not None,'history unavailable')
        labels=tuple(sorted(set(labels)));check(all(type(w)==int and 0<=w<self.meta.u for w in labels),'policy labels')
        return deepcopy(SenderInput(self.public,receipt,tuple(Cell(state.blocks[w].descriptor,state.tree.path(w)) for w in labels),historical))
    def decrypt_input(self,board,slot,labels,head_digest):
        check(0<=slot<self.meta.L,'user coordinate')
        state=self._history.get(head_digest);check(state is not None,'history unavailable')
        cells=[]
        for w in sorted(set(labels)):
            check(type(w)==int and 0<=w<self.meta.u,'attribute')
            block=state.blocks[w]
            cells.append(UserCell(Cell(block.descriptor,state.tree.path(w)),block.helpers[slot],block.tree.path(slot)))
        return deepcopy(DecryptInput(self.public,self._fixed[slot],board.resolve(head_digest),tuple(cells)))
    def sync_input(self,slot,head_digest):
        check(0<=slot<self.meta.L and head_digest in self._sync,'sync unavailable')
        man,du,dw,tree,receipt=self._sync[head_digest]
        return deepcopy(SyncInput(man,receipt,du,dw[slot],tree.path(0),tree.path(slot+1)))


def freeze(sp,registrations,*,progress=None,batch_size=0,msm_method="auto",source_receipts=None,diagnose=False):
    """Validated initial aggregate; returns only public store material.
    Each user initializes their own secrets from their Enrollment witness.
    """
    if batch_size!=0:raise ValueError('serial profile uses global YCheck; no attribute chunks')
    a._check_msm_method(msm_method)
    if source_receipts is not None:check(len(source_receipts)==sp.ctx.L,'source receipt count')
    if progress:progress('freeze: snapshot registrations')
    regs=deepcopy(list(registrations))
    check(len(regs)==sp.ctx.L and [r.slot for r in regs]==list(range(sp.ctx.L)),'roster slots')
    for index,reg in enumerate(regs):
        if progress:progress(f"freeze: verify registration {index+1}/{sp.ctx.L}")
        a.verify_registration(sp,reg,source_receipt=None if source_receipts is None else source_receipts[index])
    # Fresh independent verifier weights, generated after validating fixed input.
    a._global_y_check_validated_snapshot(sp,regs,progress=progress,diagnose=diagnose,msm_method=msm_method)
    meta=Meta(sp.ctx.pp_id,sp.ctx.sid,sp.ctx.ctx_id,sp.ctx.L,sp.ctx.u)
    blocks=[]
    for w in range(meta.u):
        if progress:progress(f"freeze: aggregate attribute {w+1}/{meta.u}")
        helpers=[a.g2_prod(regs[j].Y[i,j][w] for j in range(meta.L) if i!=j) for i in range(meta.L)]
        blocks.append(make_block(meta,w,0,a.g1_prod(reg.X[w] for reg in regs),helpers))
    fixed=[]
    for i in range(meta.L):
        V=a.g2_prod(regs[j].source_public.V[i] for j in range(meta.L) if j!=i)
        fixed.append(UserPublic(i,sp.A[i],sp.B[i],V,sp.U[i],Path(0,1,())))
    tree=Tree(domain(meta,b'FIXED'),[fixed_leaf(x) for x in fixed])
    fixed=tuple(replace(x,path=tree.path(i)) for i,x in enumerate(fixed))
    public=PublicParameters(meta,sp.g1,sp.h,sp.Omega,a.g1_prod(reg.source_public.T for reg in regs),tree.root)
    return public,make_state(meta,blocks),fixed


@dataclass(frozen=True)
class Ciphertext:
    head: bytes
    policy: Policy
    C1: Any
    C2: Any
    C3: tuple
    C4: tuple
    C5: Any
    digest: bytes


def ct_digest(public,ct):return a.sha256(b'CT',public.meta.wire(),ct.head,ct.policy.wire(),a.gt_bytes(ct.C1),a.pbytes_g1(ct.C2),seq([a.pbytes_g1(x) for x in ct.C3+ct.C4+(ct.C5,)]))


def validate_cell(meta,head,cell):
    w=cell.descriptor.attr
    check(0<=w<meta.u and cell.path.index==w and cell.path.count==meta.u,'attribute proof coordinate')
    a.member_g1(cell.descriptor.U)
    verify_path(domain(meta,b'ATTR'),cell.descriptor.wire(),cell.path,head.root)


def validate_public(public,commit,trust):
    check(public.meta==commit.head.meta and base_digest(public)==commit.head.base,'public Base/context')
    authenticate(commit.head,commit.auth,trust)


def encrypt(material,policy,message,trust,latest=None):
    check(isinstance(material,SenderInput),'sender material')
    pp=material.public;validate_public(pp,material.commit,trust);policy.validate(a.P,pp.meta.u);a.member_gt(message)
    if not material.historical:
        check(isinstance(latest,Commitment) and latest.head.digest==material.commit.head.digest,'fresh authenticated Latest required')
    labels=set(policy.rho);cells={c.descriptor.attr:c for c in material.cells}
    check(len(cells)==len(material.cells) and set(cells)==labels,'sender label material')
    for cell in cells.values():validate_cell(pp.meta,material.commit.head,cell)
    s=a.rand_scalar();v=(1,)+tuple(a.rand_scalar() for _ in range(len(policy.matrix[0])-1))
    h1=a.g1_pow(pp.g,a.rand_scalar());h2=a.g1_div(pp.h,h1);c3=[];c4=[]
    for row,w in zip(policy.matrix,policy.rho):
        sk=a.rand_scalar();share=s*sum(x*v[j] for j,x in enumerate(row) if x)%a.P
        c3.append(a.double_scalar(h2,share,cells[w].descriptor.U,-sk));c4.append(a.g1_pow(pp.g,sk))
    ct=Ciphertext(material.commit.head.digest,policy,message*pp.omega**s,a.g1_pow(pp.g,s),tuple(c3),tuple(c4),a.g1_pow(a.g1_div(h1,pp.T),s),b'')
    return replace(ct,digest=ct_digest(pp,ct))


class User:
    """Only one user's secret, correction key, checkpoint and fixed cache."""
    def __init__(self,public,fixed,secret,witness,key,commit,trust):
        validate_public(public,commit,trust)
        check(secret.slot==fixed.slot and len(witness.bits)==public.meta.u and len(witness.xi)==public.meta.u,'user initialization')
        check(fixed.path.index==fixed.slot and fixed.path.count==public.meta.L,'fixed coordinate')
        verify_path(domain(public.meta,b'FIXED'),fixed_leaf(fixed),fixed.path,public.fixed_root)
        for x in [fixed.A,fixed.B,fixed.V]:a.member_g2(x)
        a.member_g1(fixed.U)
        self.public,self.fixed,self.trust=deepcopy((public,fixed,trust))
        self.slot=secret.slot;self._zeta=secret.zeta;self._key=bytes(key)
        self._bits=tuple(witness.bits);self._xi=tuple(witness.xi);self.head=commit.head.digest;self.version=commit.head.version
        self._counters=(0,)*public.meta.u;self._receipts={self.head};self._reconstruction={};self._wloc_cache=OrderedDict();self.cache_hits=0;self.cache_misses=0
        self._fixed_factor=a.g2_div(a.g2_prod([a.g2_pow(fixed.A,self._zeta),fixed.V]),fixed.B)
        self._target=a.gt_pair(fixed.U,fixed.A)
    @property
    def bits(self):return self._bits
    def checkpoint(self):return deepcopy(self)
    def selected(self,policy):
        policy.validate(a.P,self.public.meta.u)
        key=(policy.wire(),self._bits)
        if key not in self._reconstruction:
            try:self._reconstruction[key]=tuple(reconstruct(policy,{i for i,b in enumerate(self._bits) if b==0},a.P))
            except ValueError as exc:raise a.UnsatisfiedPolicy(str(exc)) from exc
        return self._reconstruction[key]
    def labels(self,policy):return tuple(sorted({policy.rho[k] for k,x in enumerate(self.selected(policy)) if x}))
    def catch_up(self,material,*,metrics=None):
        with stage(metrics, 'client_input_s'):
            check(isinstance(material,SyncInput),'user sync material')
            pp=self.public;commit=material.commit;man=material.manifest;evt=man.event
        with stage(metrics, 'client_auth_s'):
            validate_public(pp,commit,self.trust) # actual RA/KC/Board verification, before idempotence
        with stage(metrics, 'client_bindings_s'):
            check(commit.head.manifest==man.digest and commit.head.event==evt.digest,'sync manifest')
            check(evt.meta==pp.meta and 0<=evt.attr<pp.meta.u and len(evt.nonce)==64,'sync context/shape')
            check(evt.new_version==evt.old_version+1 and evt.new_counter==evt.old_counter+1,'sync progression')
            check(commit.head.parent==evt.parent and commit.head.version==evt.new_version,'sync head event')
            check(material.common_path.index==0 and material.own_path.index==self.slot+1 and material.common_path.count==material.own_path.count==pp.meta.L+1,'delta coordinates')
        with stage(metrics, 'client_membership_s'):
            a.member_g1(material.du);a.member_g2(material.own_delta)
        with stage(metrics, 'client_paths_s'):
            verify_path(delta_domain(evt),delta_leaf(evt,0,material.du),material.common_path,man.delta_root)
            verify_path(delta_domain(evt),delta_leaf(evt,self.slot+1,material.own_delta),material.own_path,man.delta_root)
        with stage(metrics, 'client_progression_s'):
            if commit.head.digest in self._receipts:return False
            check(evt.parent==self.head and evt.old_version==self.version and evt.old_counter==self._counters[evt.attr],'sync checkpoint/parent/counter')
        with stage(metrics, 'client_prf_s'):
            chi=correction(self._key,pp.meta,self.slot,evt)
        with stage(metrics, 'client_selftest_s'):
            common=a.g1_div(material.du,a.g1_pow(pp.g,chi))
            theta=a.pair_product([(common,self.fixed.A),(a.neg(pp.g),material.own_delta)])
        with stage(metrics, 'client_state_s'):
            bits=self._bits;xi=list(self._xi);counters=list(self._counters)
            if theta==a.FQ12.one():pass
            elif theta==self._target and bits[evt.attr]==0:
                changed_bits=list(bits);changed_bits[evt.attr]=1;bits=tuple(changed_bits)
            else:raise a.InvalidSelfTest('Theta')
            xi[evt.attr]=(xi[evt.attr]+chi)%a.P;counters[evt.attr]=evt.new_counter
            if bits!=self._bits:self._reconstruction.clear()
            self._bits,self._xi,self._counters=bits,tuple(xi),tuple(counters)
            self.head=commit.head.digest;self.version=evt.new_version;self._receipts.add(self.head);self._wloc_cache.clear()
            return True
    def decrypt(self,material,ct,optimized=True,mask_mode="shift",pairing_method="auto"):
        check(mask_mode in ("shift","cached","v02"),"mask mode")
        check(isinstance(material,DecryptInput),'user decryption material')
        pp=material.public;validate_public(pp,material.commit,self.trust)
        check(base_digest(pp)==base_digest(self.public) and material.fixed.slot==self.slot,'user public material')
        check(fixed_leaf(material.fixed)==fixed_leaf(self.fixed),'fixed user binding')
        check(ct.head==material.commit.head.digest==self.head,'matching user history')
        ct.policy.validate(a.P,pp.meta.u)
        check(len(ct.C3)==len(ct.C4)==len(ct.policy.rho) and ct.digest==ct_digest(pp,ct),'ciphertext binding')
        a.member_gt(ct.C1)
        for x in (ct.C2,ct.C5)+ct.C3+ct.C4:a.member_g1(x)
        omega=self.selected(ct.policy);labels={ct.policy.rho[k] for k,o in enumerate(omega) if o}
        cells={c.cell.descriptor.attr:c for c in material.cells}
        check(len(cells)==len(material.cells) and set(cells)==labels,'own helper labels')
        wloc={}
        for w,c in cells.items():
            validate_cell(pp.meta,material.commit.head,c.cell);a.member_g2(c.helper)
            check(c.path.index==self.slot and c.path.count==pp.meta.L,'own helper coordinate')
            verify_path(domain(pp.meta,b'HELPER',w),helper_leaf(self.slot,w,c.helper),c.path,c.cell.descriptor.helper_root)
            if optimized and mask_mode=="shift":
                wloc[w]=c.helper
            elif mask_mode=="cached":
                # Every input still undergoes the same membership/path checks.
                # This cache amortizes only restoring Wloc, never authentication.
                key=(pp.meta.wire(),self.head,self.slot,self._xi[w],fixed_leaf(self.fixed),c.cell.descriptor.wire(),a.pbytes_g2(c.helper))
                if key in self._wloc_cache:
                    self.cache_hits+=1;self._wloc_cache.move_to_end(key);wloc[w]=deepcopy(self._wloc_cache[key])
                else:
                    self.cache_misses+=1;wloc[w]=a.g2_prod([c.helper,a.g2_pow(self.fixed.A,self._xi[w])])
                    self._wloc_cache[key]=deepcopy(wloc[w])
                    if len(self._wloc_cache)>128:self._wloc_cache.popitem(last=False)
            else:
                wloc[w]=a.g2_prod([c.helper,a.g2_pow(self.fixed.A,self._xi[w])])
        if not optimized:
            # Same cached fixed factor, identical validation; formula-order reference.
            slot=a.gt_pair(ct.C5,self.fixed.A)*a.gt_pair(ct.C2,self._fixed_factor)
            attr=a.FQ12.one()
            for k,o in enumerate(omega):
                if o:attr*=(a.gt_pair(ct.C3[k],self.fixed.A)*a.gt_pair(ct.C4[k],wloc[ct.policy.rho[k]]))**o
            return ct.C1*slot*attr
        same_A=a.g1_prod([ct.C5]+[a.g1_pow(x,o) for x,o in zip(ct.C3,omega) if o])
        grouped={w:[] for w in labels}
        for k,o in enumerate(omega):
            if o:grouped[ct.policy.rho[k]].append(a.g1_pow(ct.C4[k],o))
        points={w:a.g1_prod(grouped[w]) for w in labels}
        if mask_mode=="shift":
            same_A=a.g1_prod([same_A]+[a.g1_pow(points[w],self._xi[w]) for w in sorted(labels)])
        terms=[(same_A,self.fixed.A),(ct.C2,self._fixed_factor)]+[(points[w],wloc[w]) for w in sorted(labels)]
        return ct.C1*a.pair_product(terms,method=pairing_method)


def material_sizes(value):
    """Semantic encoded payload totals, not Python heap or a network transport."""
    from dataclasses import fields,is_dataclass
    sizes=defaultdict(int)
    def visit(x):
        if isinstance(x,a.Element):
            label='G' if x.kind==0 else 'GT';sizes[label]+=1;sizes['group_bytes']+=len(x.serialize())
        elif is_dataclass(x):
            for f in fields(x):visit(getattr(x,f.name))
        elif isinstance(x,bytes):sizes['bytes']+=len(x)
        elif type(x)==int:sizes['integer_values']+=1
        elif isinstance(x,(tuple,list)):
            for y in x:visit(y)
    visit(value);return dict(sizes)
