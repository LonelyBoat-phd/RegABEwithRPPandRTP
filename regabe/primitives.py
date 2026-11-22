"""RegABE registration primitives with compact linked proofs.
Native PBC Type A symmetric pairing backend with immutable group elements.
"""
from __future__ import annotations

from time import perf_counter
from dataclasses import dataclass, field, replace
from typing import Dict, List, Tuple, Iterable, Optional, Sequence, Any
import hashlib, hmac, secrets, struct, time
from .metrics import measure as measure_stage

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .type1_adapter import (GROUP, G1, G2, Z1, Z2, FQ12, curve_order,
    field_modulus, add, double, multiply, neg, pairing, eq, is_inf, is_on_curve,
    b, b2, encode, hash_point, FixedBase, Element)
BACKEND='type1_pbc'
P = curve_order
SCALAR_BYTES = (P.bit_length()+7)//8
G1_BYTES = G2_BYTES = len(G1.serialize())
GT_BYTES = len(FQ12.one().serialize())
MAGIC = b"RABW"
PROTOCOL_VERSION = 25

class RegABEError(Exception): pass
class InvalidEncoding(RegABEError): pass
class InvalidGroupElement(RegABEError): pass
class InvalidSubgroup(RegABEError): pass
class InvalidProof(RegABEError): pass
class InvalidCertificate(RegABEError): pass
class InvalidY(RegABEError): pass
class BatchFailure(RegABEError):
    def __init__(self, errors): self.errors = list(errors); super().__init__(f"batch failure at {self.errors}")
class SlotConflict(RegABEError): pass
class StaleParent(RegABEError): pass
class Replay(RegABEError): pass
class InvalidCounter(RegABEError): pass
class InvalidPath(RegABEError): pass
class InvalidSelfTest(RegABEError): pass
class UnsatisfiedPolicy(RegABEError): pass
class UnavailableHistory(RegABEError): pass
class UncertainCommit(RegABEError): pass
class AuthorizationFailure(RegABEError): pass


def i2b(x: int, n: int = SCALAR_BYTES) -> bytes:
    if x < 0 or x >= (1 << (8*n)): raise InvalidEncoding("integer width")
    return x.to_bytes(n, "big")

def b2i(x: bytes) -> int:
    return int.from_bytes(x, "big")

def scalar_bytes(x: int) -> bytes: return i2b(x % P)
def rand_scalar() -> int: return secrets.randbelow(P)

def sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts: h.update(struct.pack(">I", len(p))); h.update(p)
    return h.digest()
def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts: h.update(struct.pack(">I", len(p))); h.update(p)
    return h.digest()
def h_scalar(*parts: bytes) -> int:
    limit=2**512-(2**512%P)
    for counter in range(256):
        x=int.from_bytes(sha512(b"REGABE25-FIELD",*parts,i2b(counter,4)),"big")
        if x<limit: return x%P
    raise InvalidEncoding("hash rejection limit")
def nonzero_scalar(*parts: bytes) -> int:
    x=h_scalar(*parts)
    return x if x else 1

def centered_multiply(point,k):
    k%=P
    return neg(multiply(point,P-k)) if k>P//2 else multiply(point,k)

class _FixedBaseTable:
    def __init__(self,base,group):
        if group not in ('G1','G2'):raise ValueError('group')
        member_g1(base)
        self.table=FixedBase(base)
    def multiply(self,scalar):return self.table.multiply(scalar)


def _registration_tables(sp):
    # Canonical current coordinates bind the cache, rather than object identity.
    # Changing any base discards the previous tables. No witness is cached.
    key=(pbytes_g1(sp.g1),pbytes_g1(sp.H0),tuple(pbytes_g2(a) for a in sp.A))
    cached=sp._registration_precompute
    if cached is None or cached[0] != key:
        cached=(key,(_FixedBaseTable(sp.g1,"G1"),_FixedBaseTable(sp.H0,"G1"),
                     tuple(_FixedBaseTable(a,"G2") for a in sp.A)))
        sp._registration_precompute=cached
    return cached[1]


def g1_pow(x,k): return centered_multiply(x,k)
def g2_pow(x,k): return centered_multiply(x,k)
def g1_prod(xs: Iterable):return GROUP.product(xs)
def g2_prod(xs: Iterable):return GROUP.product(xs)
def g1_div(x, y): return add(x, neg(y))
def g2_div(x, y): return add(x, neg(y))
def eq_g1(x, y): return x==y if BACKEND=="charm" else eq(x,y)
def eq_g2(x, y): return x==y if BACKEND=="charm" else eq(x,y)
def gt_pair(x1,x2):return GROUP.pair(x1,x2)
def gt_pair_g2g1(x2,x1):return gt_pair(x1,x2)
def pair_product(terms,method='auto'):
    if method not in ('auto','native','sequential','simultaneous'):raise ValueError('pairing method')
    terms=tuple(terms)
    return gt_prod(gt_pair(x,y) for x,y in terms) if method=='sequential' else GROUP.pair_product(terms)
def simultaneous_pair_product(terms):return GROUP.pair_product(terms)
def double_scalar(x,n,y,m):return GROUP.pow2(x,n,y,m)


def pairing_equal(x,a,g,y):
    return pair_product([(x,a),(neg(g),y)])==FQ12.one()

def member_g1(x):
    if not is_on_curve(x,b) or not is_inf(multiply(x,P)): raise InvalidGroupElement("G1 member")

def member_g2(x):
    if not is_on_curve(x,b2) or not is_inf(multiply(x,P)): raise InvalidGroupElement("G2 member")

def member_many(points):
    try:GROUP.member_many(points)
    except (TypeError,ValueError) as exc:raise InvalidGroupElement('source group member') from exc


def member_gt(x):
    if not GROUP.member(x,1):raise InvalidGroupElement('GT member')

def gt_prod(xs: Iterable):
    out = FQ12.one()
    for x in xs: out *= x
    return out

def pbytes_g1(p):
    if not isinstance(p,Element) or p.kind!=0:raise InvalidGroupElement('source type')
    return encode(p)
def pbytes_g2(p):return pbytes_g1(p)
def gt_bytes(x):
    if not isinstance(x,Element) or x.kind!=1:raise InvalidGroupElement('target type')
    return encode(x)

def encode_record(fields: Dict[int, bytes], schema: bytes = b"core", version: int = PROTOCOL_VERSION) -> bytes:
    if not isinstance(schema, bytes) or len(schema) > 65535: raise InvalidEncoding("schema")
    tags = sorted(fields)
    if len(tags) != len(set(tags)) or any(t < 0 or t > 65535 for t in tags): raise InvalidEncoding("tags")
    out = bytearray(MAGIC + struct.pack(">HH", version, len(schema)) + schema + struct.pack(">H", len(tags)))
    prev = -1
    for t in tags:
        if t <= prev: raise InvalidEncoding("ordering")
        v = fields[t]
        if not isinstance(v, bytes) or len(v) > 0xffffffff: raise InvalidEncoding("field")
        out += struct.pack(">HI", t, len(v)) + v; prev = t
    return bytes(out)

def decode_record(data: bytes, expected_schema: Optional[bytes] = None, expected_version: int = PROTOCOL_VERSION) -> Tuple[int, bytes, Dict[int, bytes]]:
    if len(data) < 10 or data[:4] != MAGIC: raise InvalidEncoding("magic")
    pos = 4; ver, slen = struct.unpack_from(">HH", data, pos); pos += 4
    if ver != expected_version: raise InvalidEncoding("protocol version")
    if pos + slen + 2 > len(data): raise InvalidEncoding("schema length")
    schema = data[pos:pos+slen]; pos += slen
    if expected_schema is not None and schema != expected_schema: raise InvalidEncoding("schema id")
    count = struct.unpack_from(">H", data, pos)[0]; pos += 2
    fields: Dict[int, bytes] = {}; prev = -1
    for _ in range(count):
        if pos + 6 > len(data): raise InvalidEncoding("truncated field header")
        tag, n = struct.unpack_from(">HI", data, pos); pos += 6
        if tag <= prev or tag in fields: raise InvalidEncoding("duplicate/order")
        if pos + n > len(data): raise InvalidEncoding("truncated field")
        fields[tag] = data[pos:pos+n]; pos += n; prev = tag
    if pos != len(data): raise InvalidEncoding("trailing bytes")
    return ver, schema, fields

def merkle_root(leaves: Sequence[bytes], tree_id: bytes = b"default") -> bytes:
    if not leaves: return sha256(b"REGABE-MERKLE-EMPTY", tree_id)
    level = [sha256(b"REGABE-MERKLE-LEAF", tree_id, i2b(i, 4), x) for i,x in enumerate(leaves)]
    while len(level) > 1:
        nxt=[]
        for i in range(0,len(level),2):
            r = level[i+1] if i+1 < len(level) else level[i]
            nxt.append(sha256(b"REGABE-MERKLE-NODE", tree_id, level[i], r))
        level=nxt
    return level[0]

def merkle_proof(leaves: Sequence[bytes], index: int, tree_id: bytes=b"default") -> List[Tuple[bytes,bool]]:
    if index < 0 or index >= len(leaves): raise InvalidPath("leaf index")
    level=[sha256(b"REGABE-MERKLE-LEAF",tree_id,i2b(i,4),x) for i,x in enumerate(leaves)]; p=[]; idx=index
    while len(level)>1:
        sib=idx-1 if idx%2 else idx+1
        if sib>=len(level): sib=idx
        p.append((level[sib], idx%2==1)); nxt=[]
        for i in range(0,len(level),2): nxt.append(sha256(b"REGABE-MERKLE-NODE",tree_id,level[i],level[i+1] if i+1<len(level) else level[i]))
        level=nxt; idx//=2
    return p

def verify_merkle(leaf: bytes, index: int, proof: Sequence[Tuple[bytes,bool]], root: bytes, tree_id: bytes=b"default") -> bool:
    h=sha256(b"REGABE-MERKLE-LEAF",tree_id,i2b(index,4),leaf); idx=index
    for sib,left in proof:
        h=sha256(b"REGABE-MERKLE-NODE",tree_id,sib,h) if left else sha256(b"REGABE-MERKLE-NODE",tree_id,h,sib); idx//=2
    return h==root

@dataclass
class Context:
    L: int = 2
    u: int = 1
    version: int = PROTOCOL_VERSION
    pp_id: bytes = b""
    sid: bytes = b""
    ctx_id: bytes = b""
    schema_id: bytes = b""
    used_nonces: set = field(default_factory=set)
    reserved_slots: set = field(default_factory=set)

@dataclass
class SourceSecret:
    slot: int
    zeta: int

@dataclass
class SourcePublic:
    slot: int
    T: Any
    Q: Any
    V: Dict[int, Any]

@dataclass
class ACAKeys:
    private: Ed25519PrivateKey
    public: bytes

@dataclass
class Certificate:
    identity: int
    slot: int
    ctx_id: bytes
    statement_digest: bytes
    signature: bytes
    aca_public: bytes
    def message(self) -> bytes:
        return encode_record({1:i2b(self.identity,4),2:i2b(self.slot,4),3:self.ctx_id,4:self.statement_digest}, b"aca-cert")
    def verify(self):
        try: Ed25519PublicKey.from_public_bytes(self.aca_public).verify(self.signature, self.message())
        except (InvalidSignature,ValueError) as e: raise InvalidCertificate(str(e))

def registration_sequence(parts):
    fields = tuple(parts)
    return i2b(len(fields), 4) + b"".join(i2b(len(field), 4) + field for field in fields)


def registration_source_wire(pk):
    seq = registration_sequence
    return seq([i2b(pk.slot, 4), pbytes_g1(pk.T), pbytes_g2(pk.Q),
                seq(seq([i2b(j, 4), pbytes_g2(v)]) for j, v in sorted(pk.V.items()))])


@dataclass(frozen=True)
class Registration:
    slot: int
    source_public: SourcePublic
    C: Any
    X: tuple
    Y: dict
    certificate: Certificate
    splits: tuple
    challenge: int
    responses: tuple

    def public_statement(self, setup):
        seq = registration_sequence
        return seq([b'SUPPLEMENT-PRIVATE-v1', setup.ctx.pp_id, setup.ctx.schema_id,
                    registration_source_wire(self.source_public), pbytes_g1(self.C),
                    seq(pbytes_g1(x) for x in self.X),
                    seq(seq([i2b(i, 4), i2b(j, 4), seq(pbytes_g2(y) for y in ys)])
                        for (i, j), ys in sorted(self.Y.items())),
                    self.certificate.message(), self.certificate.signature])

    def wire(self, setup):
        seq = registration_sequence
        return seq([self.public_statement(setup), seq(pbytes_g1(d) for d in self.splits),
                    scalar_bytes(self.challenge),
                    seq(b''.join(scalar_bytes(z) for z in row) for row in self.responses)])


@dataclass(frozen=True)
class RegistrationWitness:
    bits: tuple
    opening: int
    xi: tuple

@dataclass(frozen=True)
class Enrollment:
    public: Registration
    witness: RegistrationWitness

@dataclass
class SetupParams:
    ctx: Context
    g1: Any; g2: Any
    H0: Any; Hw: List[Any]
    d: List[int]; d_max: int
    A: List[Any]; B: List[Any]; Pk: List[Any]; U: List[Any]
    W: Dict[Tuple[int,int],Any]
    Omega: Any
    h: Any
    base_digest: bytes
    _registration_precompute: Any = field(default=None,init=False,repr=False,compare=False)
    aca_public: bytes = b""
    fixed_digest: bytes = b""

class Authority:
    """ACA issuance service used by the local experiment driver."""
    def __init__(self):
        self.aca=ACAKeys(Ed25519PrivateKey.generate(),b"")
        self.aca.public=self.aca.private.public_key().public_bytes_raw()


def setup(L: int=2, u: int=1, seed: Optional[bytes]=None) -> Tuple[SetupParams, Authority]:
    if type(L)!=int or type(u)!=int or L < 2 or u < 1: raise ValueError("L/u")
    ctx=Context(L=L,u=u,pp_id=sha256(b"pp",BACKEND.encode(),i2b(L,4),i2b(u,4)),sid=sha256(b"sid",seed or secrets.token_bytes(16)),ctx_id=sha256(b"ctx",seed or secrets.token_bytes(16)),schema_id=sha256(b"schema",i2b(u,4)))
    # Compact ternary progression-free, double-free set; share equal off-diagonal sums.
    from .indices import compact_set
    d=list(compact_set(L)); dmax=3*max(d)
    a=secrets.randbelow(P-1)+1; beta0=secrets.randbelow(P-1)+1; deltas=[rand_scalar() for _ in range(L)]
    t=[pow(a,x,P) for x in d]; alpha=(-pow(a,dmax,P))%P; gamma=sum(pow(a,dmax-x,P) for x in d)%P
    A=[g2_pow(G2,t[i]) for i in range(L)]; B=[g2_pow(G2,(alpha+gamma*t[i])%P) for i in range(L)]; Pk=[g2_pow(G2,deltas[i]) for i in range(L)]; U=[g1_pow(G1,beta0*t[i]) for i in range(L)]
    sums=sorted({d[i]+d[j] for i in range(L) for j in range(i+1,L)})
    unique_W={z:g2_pow(G2,beta0*pow(a,z,P)%P) for z in sums}
    W={(i,j):unique_W[d[i]+d[j]] for i in range(L) for j in range(L) if i!=j}
    Omega=gt_pair(g1_pow(G1,1),g2_pow(G2,alpha))
    h=g1_pow(G1,gamma)
    ctx.pp_id=sha256(b"REGABE25-PPID",BACKEND.encode(),i2b(P),i2b(L,4),i2b(u,4),ctx.sid,ctx.ctx_id,ctx.schema_id,pbytes_g1(G1),pbytes_g2(G2),pbytes_g1(h),gt_bytes(Omega),*[pbytes_g2(x) for x in A+B+Pk],*[pbytes_g1(x) for x in U],*[str(z).encode()+pbytes_g2(x) for z,x in sorted(unique_W.items())])
    hash_to_G1=hash_point
    H0=hash_to_G1(ctx.pp_id+ctx.sid+ctx.ctx_id,b"REGABE25-PROFILE-BLIND-TYPE1-A-HASH_",hashlib.sha256)
    Hw=[hash_to_G1(ctx.schema_id+ctx.sid+ctx.ctx_id+i2b(w,4),b"REGABE25-PROFILE-ATTR-TYPE1-A-HASH_",hashlib.sha256) for w in range(u)]
    manifest=encode_record({1:i2b(L,4),2:i2b(u,4),3:ctx.pp_id,4:ctx.sid,5:ctx.ctx_id,6:ctx.schema_id,7:b"PBC-TYPE-A"+bytes.fromhex(GROUP.parameter_sha256)},b"manifest")
    # W values are derived directly as scalar multiples of G2; curve-membership
    # is checked for every published W, while the expensive subgroup test is
    # applied to the independent setup bases and source objects.
    points=[H0,*Hw,*A,*U]
    if any(is_inf(x) for x in points): raise InvalidGroupElement("setup produced unit")
    if any(not is_inf(multiply(x,P)) for x in points): raise InvalidSubgroup("setup subgroup")
    if any(is_inf(x) or not is_on_curve(x,b2) for x in unique_W.values()): raise InvalidGroupElement("W setup")
    base_digest=sha256(b"REGABE-BASE",manifest,pbytes_g1(h),pbytes_g1(H0),*[pbytes_g1(x) for x in Hw+U],*[pbytes_g2(x) for x in A+B+Pk],*[str(z).encode()+pbytes_g2(x) for z,x in sorted(unique_W.items())])
    auth=Authority()
    return SetupParams(ctx,G1,G2,H0,Hw,d,dmax,A,B,Pk,U,W,Omega,h,base_digest,auth.aca.public), auth


def source_keygen(sp: SetupParams, slot: int) -> Tuple[SourceSecret, SourcePublic]:
    if slot < 0 or slot >= sp.ctx.L: raise SlotConflict("slot")
    zeta=rand_scalar(); T=g1_pow(sp.g1,zeta); Q=g2_pow(sp.Pk[slot],zeta); V={j:g2_pow(sp.A[j],zeta) for j in range(sp.ctx.L) if j!=slot}
    sec=SourceSecret(slot,zeta)
    return sec, SourcePublic(slot,T,Q,V)

def source_key_valid(sp: SetupParams, pub: SourcePublic) -> bool:
    if type(pub.slot)!=int or not 0<=pub.slot<sp.ctx.L: return False
    if set(pub.V) != set(range(sp.ctx.L)) - {pub.slot}: return False
    try:
        member_many((pub.T, pub.Q, *pub.V.values()))
    except InvalidGroupElement:
        return False
    if not pairing_equal(pub.T,sp.Pk[pub.slot],sp.g1,pub.Q): return False
    return all(pairing_equal(pub.T,sp.A[j],sp.g1,v) for j,v in pub.V.items())


def registration_certificate(sp, auth, slot, pk, obj, identity=None):
    digest = sha256(b'SUPPLEMENT-CERT-v1', sp.ctx.pp_id, sp.ctx.schema_id,
                    registration_source_wire(pk), obj)
    cert = Certificate(slot if identity is None else identity, slot, sp.ctx.ctx_id,
                       digest, b'', auth.aca.public)
    cert.signature = auth.aca.private.sign(cert.message())
    return cert


def verify_registration_certificate(sp, pk, cert, obj):
    if cert.slot != pk.slot or cert.ctx_id != sp.ctx.ctx_id:
        raise InvalidCertificate("certificate slot/context")
    if cert.aca_public != sp.aca_public:
        raise InvalidCertificate("untrusted ACA")
    expected = sha256(b'SUPPLEMENT-CERT-v1', sp.ctx.pp_id, sp.ctx.schema_id,
                      registration_source_wire(pk), obj)
    if cert.statement_digest != expected:
        raise InvalidCertificate("certificate profile binding")
    cert.verify()


def _proof_challenge(sp, reg, splits, first_messages):
    seq = registration_sequence
    return h_scalar(seq([b'REGSIGMA26', sp.ctx.pp_id, reg.public_statement(sp),
                         seq(pbytes_g1(d) for d in splits),
                         seq(seq(pbytes_g1(x) for x in row) for row in first_messages)]))


def _branch_statement(sp, slot, attr, split, x, branch):
    if branch == 0:
        return split, x
    return g1_div(split, sp.Hw[attr]), g1_div(x, sp.U[slot])


def _generate_compact_registration(sp, auth, slot, bits, source_secret, source_public,
                                   identity=None, *, fixed_base=True, metrics=None):
    """Fresh registration randomness belongs to this invocation, not SourceKeyGen.

    Replaying an existing Enrollment reuses its bytes/witness. Calling RegGen
    again creates a new record and independent masks. No ACA review service is
    modeled here; certification remains the existing local signing operation.
    """
    if len(bits) != sp.ctx.u or any(type(bit) is not int or bit not in (0, 1) for bit in bits):
        raise ValueError("bits")
    if (type(slot) is not int or not 0 <= slot < sp.ctx.L or
            source_secret.slot != slot or source_public.slot != slot):
        raise AuthorizationFailure("source key slot")
    if fixed_base:
        tg, th, ta = measure_stage(metrics, 'gen_precompute_lookup_s', lambda: _registration_tables(sp))
        pow_g, pow_h = tg.multiply, th.multiply
        pow_a = lambda i, k: ta[i].multiply(k)
    else:
        pow_g = lambda k: g1_pow(sp.g1, k)
        pow_h = lambda k: g1_pow(sp.H0, k)
        pow_a = lambda i, k: g2_pow(sp.A[i], k)

    opening, xi = measure_stage(metrics, 'gen_randomness_s',
        lambda: (rand_scalar(), tuple(rand_scalar() for _ in range(sp.ctx.u))))
    profile_bases = tuple(sp.Hw[w] if bit else Z1 for w, bit in enumerate(bits))
    C = measure_stage(metrics, 'gen_commitment_s', lambda: g1_prod([pow_h(opening), *profile_bases]))
    X = measure_stage(metrics, 'gen_X_s', lambda: tuple(
        g1_prod([sp.U[slot] if bit else Z1, pow_g(xi[w])]) for w, bit in enumerate(bits)))
    Y = measure_stage(metrics, 'gen_Y_s', lambda: {
        (i, slot): [g2_prod([sp.W[i, slot] if bit else Z2, pow_a(i, xi[w])])
                    for w, bit in enumerate(bits)] for i in range(sp.ctx.L) if i != slot})
    def split_commitments():
        ts = [rand_scalar() for _ in range(sp.ctx.u - 1)]
        ts.append((opening - sum(ts)) % P)
        return ts, tuple(g1_prod([pow_h(t), base]) for t, base in zip(ts, profile_bases))
    ts, splits = measure_stage(metrics, 'gen_splits_s', split_commitments)
    cert = measure_stage(metrics, 'gen_certificate_s', lambda:
        registration_certificate(sp, auth, slot, source_public, pbytes_g1(C), identity))
    record = Registration(slot, source_public, C, X, Y, cert, splits[:-1], 0, ())

    def proof_first():
        first_messages, coins = [], []
        for w, bit in enumerate(bits):
            simulated = 1 - bit
            cs, zt, zx, kt, kx = (rand_scalar() for _ in range(5))
            branch_p, branch_q = _branch_statement(sp, slot, w, splits[w], X[w], simulated)
            pairs = [None, None]
            pairs[simulated] = (double_scalar(sp.H0, zt, branch_p, -cs),
                                double_scalar(sp.g1, zx, branch_q, -cs))
            pairs[bit] = (pow_h(kt), pow_g(kx))
            first_messages.append((*pairs[0], *pairs[1]))
            coins.append((cs, zt, zx, kt, kx))
        return first_messages, coins
    first_messages, coins = measure_stage(metrics, 'gen_proof_first_s', proof_first)
    challenge = measure_stage(metrics, 'gen_proof_hash_s',
        lambda: _proof_challenge(sp, record, splits, first_messages))
    def proof_responses():
        responses = []
        for w, bit in enumerate(bits):
            cs, zt, zx, kt, kx = coins[w]
            cr = (challenge - cs) % P
            real = ((kt + cr * ts[w]) % P, (kx + cr * xi[w]) % P)
            responses.append((cr, *real, zt, zx) if bit == 0 else (cs, zt, zx, *real))
        return tuple(responses)
    responses = measure_stage(metrics, 'gen_proof_responses_s', proof_responses)
    return Enrollment(replace(record, challenge=challenge, responses=responses),
                      RegistrationWitness(tuple(bits), opening, xi))


def generate_registration(sp, auth, slot, bits, source_secret, source_public, identity=None,
                          *, fixed_base=True, source_receipt=None, metrics=None):
    if (source_secret.slot != slot or source_public.slot != slot or
            not _source_valid_or_receipt(sp, source_public, source_receipt)):
        raise AuthorizationFailure("source key")
    return _generate_compact_registration(sp, auth, slot, bits, source_secret, source_public,
                                          identity, fixed_base=fixed_base, metrics=metrics)


def verify_registration(sp, reg, *, source_receipt=None, proof_pair=double_scalar, metrics=None):
    def measure(name, operation):
        if metrics is None:
            return operation()
        start = perf_counter()
        result = operation()
        metrics[name] = metrics.get(name, 0.0) + perf_counter() - start
        return result

    if (not isinstance(reg, Registration) or type(reg.slot) is not int or
            not 0 <= reg.slot < sp.ctx.L or reg.source_public.slot != reg.slot or
            len(reg.X) != sp.ctx.u or len(reg.responses) != sp.ctx.u or
            len(reg.splits) != sp.ctx.u - 1):
        raise InvalidProof("registration shape")
    if (set(reg.Y) != {(i, reg.slot) for i in range(sp.ctx.L) if i != reg.slot} or
            any(len(row) != sp.ctx.u for row in reg.Y.values())):
        raise InvalidProof("Y shape")
    if type(reg.challenge) is not int or not 0 <= reg.challenge < P:
        raise InvalidProof("challenge scalar")
    for row in reg.responses:
        if len(row) != 5 or any(type(z) is not int or not 0 <= z < P for z in row):
            raise InvalidProof("response scalars")
    if not measure('record_source_s', lambda: _source_valid_or_receipt(sp, reg.source_public, source_receipt)):
        raise InvalidProof("source key")
    measure('record_membership_s', lambda: member_many((reg.C, *reg.X, *reg.splits)))
    measure('record_certificate_s',
            lambda: verify_registration_certificate(sp, reg.source_public, reg.certificate, pbytes_g1(reg.C)))

    def reconstruct_proof():
        splits = (*reg.splits, g1_div(reg.C, g1_prod(reg.splits)))
        first_messages = []
        for w, (c0, z0t, z0x, z1t, z1x) in enumerate(reg.responses):
            row = []
            for branch, (challenge, zt, zx) in enumerate(((c0, z0t, z0x),
                                                         ((reg.challenge - c0) % P, z1t, z1x))):
                branch_p, branch_q = _branch_statement(sp, reg.slot, w, splits[w], reg.X[w], branch)
                row.extend((proof_pair(sp.H0, zt, branch_p, -challenge),
                            proof_pair(sp.g1, zx, branch_q, -challenge)))
            first_messages.append(tuple(row))
        return splits, first_messages

    splits, first_messages = measure('record_proof_reconstruct_s', reconstruct_proof)
    if measure('record_hash_s', lambda: _proof_challenge(sp, reg, splits, first_messages)) != reg.challenge:
        raise InvalidProof("compact linked proof")
    return True


def y_check(sp: SetupParams, regs: Sequence[Registration], receiver: int, submitter: int, w: int) -> bool:
    reg=regs[submitter]; y=reg.Y[(receiver,submitter)][w]
    if not is_inf(multiply(reg.X[w],P)) or not is_inf(multiply(y,P)):
        raise InvalidGroupElement("YCheck point")
    return pairing_equal(reg.X[w],sp.A[receiver],sp.g1,y)

def ycheck_batch_plan(L, u, batch_size=0):
    """All equations are covered; batch_size is a cap, never a sample count."""
    if type(L)!=int or L<2 or type(u)!=int or u<1:
        raise ValueError("L>=2 and u>=1 required")
    if type(batch_size)!=int or batch_size<0:
        raise ValueError("batch_size must be an integer >=0 (0 means all attributes)")
    effective=u if batch_size==0 else min(batch_size,u)
    chunks=(u+effective-1)//effective
    return {'requested_batch_size':batch_size,'effective_batch_size':effective,
            'chunks_per_receiver_submitter':chunks,
            'batches_per_verifier':L*(L-1)*chunks,
            'equations_per_verifier':L*(L-1)*u,
            'coverage':'all_equations','weight_distribution':'uniform_nonzero_field'}


def _check_msm_method(method):
    if method not in ('auto','naive','native','pippenger'):raise ValueError('MSM method')
def _prime_order_msm(points,scalars,group,method='auto'):
    _check_msm_method(method)
    if group not in ('G1','G2'):raise ValueError('MSM group')
    points=tuple(points);scalars=tuple(scalars)
    if len(points)!=len(scalars):raise ValueError('MSM lengths')
    if method=='naive':return g1_prod(g1_pow(x,k) for x,k in zip(points,scalars))
    return GROUP.msm(points,scalars)


def batch_y_check(sp: SetupParams, regs: Sequence[Registration], receiver: int,
                  submitter: int, *, locate=True, batch_size=0, msm_method='auto'):
    """Validate every equation using fresh private nonzero weights per chunk.

    Inputs must remain fixed before and during verification. For a fixed
    erroneous prime-order chunk, false acceptance is at most 1/(P-1).
    No external weights or skip-validation flag are accepted.
    """
    ycheck_batch_plan(sp.ctx.L,sp.ctx.u,batch_size);_check_msm_method(msm_method)
    if type(receiver)!=int or type(submitter)!=int or not 0<=receiver<sp.ctx.L or not 0<=submitter<sp.ctx.L or receiver==submitter:
        raise ValueError("YCheck coordinates")
    reg=regs[submitter]
    if len(reg.X)!=sp.ctx.u or (receiver,submitter) not in reg.Y or len(reg.Y[receiver,submitter])!=sp.ctx.u:
        raise InvalidY("YCheck shape")
    member_g2(sp.A[receiver])
    if is_inf(sp.A[receiver]):raise InvalidGroupElement("YCheck source identity")
    for x,y in zip(reg.X,reg.Y[receiver,submitter]):
        member_g1(x);member_g2(y)
    return _batch_y_check_prime_order(sp,regs,receiver,submitter,locate=locate,
                                     batch_size=batch_size,msm_method=msm_method)


def _batch_y_check_prime_order(sp, regs, receiver, submitter, *, locate=True,
                              batch_size=0, msm_method='auto'):
    """Internal only: caller has validated shapes and all prime-order members."""
    size=ycheck_batch_plan(sp.ctx.L,sp.ctx.u,batch_size)['effective_batch_size']
    reg=regs[submitter];errors=[]
    for start in range(0,sp.ctx.u,size):
        stop=min(start+size,sp.ctx.u)
        # Every coordinate, tail chunks included, gets a fresh private weight.
        weights=[secrets.randbelow(P-1)+1 for _ in range(start,stop)]
        xa=_prime_order_msm(reg.X[start:stop],weights,'G1',msm_method)
        ya=_prime_order_msm(reg.Y[receiver,submitter][start:stop],weights,'G2',msm_method)
        if pairing_equal(xa,sp.A[receiver],sp.g1,ya):continue
        if not locate:raise BatchFailure([(receiver,submitter,-1)])
        bad=[(receiver,submitter,w) for w in range(start,stop)
             if not y_check(sp,regs,receiver,submitter,w)]
        errors.extend(bad or [(receiver,submitter,-1)])
    if errors:raise BatchFailure(errors)
    return []


def _all_y_check_batches(sp, regs, checker, *, progress=None, batch_size=0,
                        msm_method='auto'):
    plan=ycheck_batch_plan(sp.ctx.L,sp.ctx.u,batch_size)
    errors=[];done=0;total=sp.ctx.L*(sp.ctx.L-1);stride=max(1,total//100)
    if progress:progress(f"YCheck random-weighted pairs 0/{total}; chunks={plan['batches_per_verifier']}; cap={plan['effective_batch_size']}")
    for j in range(sp.ctx.L):
        for i in range(sp.ctx.L):
            if i==j:continue
            try:checker(sp,regs,i,j,batch_size=batch_size,msm_method=msm_method)
            except BatchFailure as e:errors.extend(e.errors)
            done+=1
            if progress and (done==1 or done%stride==0 or done==total):progress(f"YCheck completed {done}/{total} receiver/submitter pairs")
    if errors:raise BatchFailure(errors)
    return []


def all_y_check(sp: SetupParams, regs: Sequence[Registration], batch=True, *,
                progress=None, batch_size=0, msm_method='auto'):
    """Check all Y relations globally by default, or select explicit diagnostic modes."""
    ycheck_batch_plan(sp.ctx.L,sp.ctx.u,batch_size);_check_msm_method(msm_method)
    if batch and batch_size == 0:
        global_y_check(sp, regs, progress=progress, msm_method=msm_method)
        return []
    if batch:
        return _all_y_check_batches(sp,regs,batch_y_check,progress=progress,
                                   batch_size=batch_size,msm_method=msm_method)
    errors=[]
    for j in range(sp.ctx.L):
        for i in range(sp.ctx.L):
            if i==j:continue
            # Defensive public checks are also required on the deterministic path.
            reg=regs[j]
            if len(reg.X)!=sp.ctx.u or (i,j) not in reg.Y or len(reg.Y[i,j])!=sp.ctx.u:
                raise InvalidY("YCheck shape")
            member_g2(sp.A[i])
            if is_inf(sp.A[i]):raise InvalidGroupElement("YCheck source identity")
            for x,y in zip(reg.X,reg.Y[i,j]):member_g1(x);member_g2(y)
            errors.extend((i,j,w) for w in range(sp.ctx.u) if not y_check(sp,regs,i,j,w))
    if errors:raise BatchFailure(errors)
    return []

import weakref
class _SourceReceipt:pass
_source_receipts=weakref.WeakKeyDictionary()
def _source_fingerprint(sp,pub):
    return sha256(b'SOURCE-VALIDATED',sp.ctx.pp_id,i2b(pub.slot,4),pbytes_g1(pub.T),pbytes_g2(pub.Q),
                  pbytes_g1(sp.g1),pbytes_g2(sp.Pk[pub.slot]),*[pbytes_g2(x) for x in sp.A],
                  *[i2b(j,4)+pbytes_g2(x) for j,x in sorted(pub.V.items())])
def validate_source(sp,pub):
    if not source_key_valid(sp,pub):raise InvalidProof('source IsValid')
    token=_SourceReceipt();_source_receipts[token]=_source_fingerprint(sp,pub);return token
def _source_valid_or_receipt(sp,pub,receipt=None):
    if receipt is None:return source_key_valid(sp,pub)
    return _source_receipts.get(receipt)==_source_fingerprint(sp,pub)
def global_y_check(sp,regs,*,diagnose=False,msm_method='auto',progress=None):
    from .validation import verify_all_y
    return verify_all_y(sp,regs,diagnose=diagnose,msm_method=msm_method,progress=progress)

def _global_y_check_validated_snapshot(sp,regs,**kwargs):
    from .validation import verify_all_y
    return verify_all_y(sp,regs,_checked_X=True,**kwargs)
