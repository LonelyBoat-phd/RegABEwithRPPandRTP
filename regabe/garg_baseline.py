"""Independent GLWW24 Construction 4.3 research baseline, native Type-1.
Uses the same symmetric pairing backend, compact indices and algebraic
optimizations as the wrapper. This does not certify concrete BDHE security.
"""
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from . import primitives as a
from .policy import reconstruct


def progression_set(L, mode="compact"):
    if type(L) is not int or L < 2:
        raise ValueError("L >= 2 required")
    if mode!='compact':raise ValueError('This profile uses compact indices only')
    from .indices import compact_set
    d=compact_set(L)
    values = set(d)
    if len(values) != L or any(2*x in values for x in d):
        raise ValueError("not double-free")
    if any(x != y and (x+y) % 2 == 0 and (x+y)//2 in values
           for x in d for y in d):
        raise ValueError("not progression-free")
    return d


@dataclass(frozen=True)
class Parameters:
    ctx: Any
    g1: Any
    g2: Any
    h: Any
    Omega: Any
    A: tuple
    B: tuple
    Pk: tuple
    U: tuple
    W: dict
    d: tuple
    mode: str


def setup(L=16, u=32, *, set_mode="compact"):
    if type(u) is not int or u < 1:
        raise ValueError("u >= 1 required")
    d = progression_set(L, set_mode)
    dmax = 3*max(d)
    # Match v0.7 nonzero conditioning and orientation. Setup scalars are local.
    aa, beta = a.secrets.randbelow(a.P-1)+1, a.secrets.randbelow(a.P-1)+1
    t = [pow(aa, x, a.P) for x in d]
    alpha = -pow(aa, dmax, a.P) % a.P
    gamma = sum(pow(aa, dmax-x, a.P) for x in d) % a.P
    A = tuple(a.g2_pow(a.G2, x) for x in t)
    B = tuple(a.g2_pow(a.G2, alpha+gamma*x) for x in t)
    Pk = tuple(a.g2_pow(a.G2, a.rand_scalar()) for _ in d)
    U = tuple(a.g1_pow(a.G1, beta*x) for x in t)
    # Publish one group value per distinct off-diagonal sum, with a public index.
    sums = sorted({d[i]+d[j] for i in range(L) for j in range(i+1, L)})
    W = {z: a.g2_pow(a.G2, beta*pow(aa, z, a.P)) for z in sums}
    h = a.g1_pow(a.G1, gamma)
    omega = a.gt_pair(a.g1_pow(a.G1, 1), a.g2_pow(a.G2, alpha))
    for point in A:
        a.member_g2(point)
        if a.is_inf(point):
            raise a.InvalidGroupElement("unit A")
    for point in U:
        a.member_g1(point)
        if a.is_inf(point):
            raise a.InvalidGroupElement("unit U")
    if any(a.is_inf(point) or not a.is_on_curve(point, a.b2) for point in W.values()):
        raise a.InvalidGroupElement("setup W")
    # Digest all published group values; no commitments, ACA, trees or masks.
    digest = a.sha256(b"GLWW24-TYPE1", a.i2b(L, 4), set_mode.encode(),
                     a.pbytes_g1(h), a.gt_bytes(omega),
                     *[a.pbytes_g2(p) for p in A+B+Pk],
                     *[a.pbytes_g1(p) for p in U],
                     *[str(z).encode()+a.pbytes_g2(W[z]) for z in sums])
    return Parameters(SimpleNamespace(L=L, u=u, pp_id=digest), a.G1, a.G2,
                      h, omega, A, B, Pk, U, W, d, set_mode)


def keygen(pp, slot):
    # Passing an empty xi avoids generating wrapper-only attribute masks.
    return a.source_keygen(pp, slot)


def is_valid(pp, public):
    return a.source_key_valid(pp, public)


@dataclass(frozen=True)
class Aggregate:
    pp: Parameters
    T: Any
    V: tuple
    U: tuple
    W: tuple
    profiles: tuple


def aggregate(pp, public_keys, profiles):
    """Source Aggregate mathematics; IsValid is separately measured by driver.

    Profiles are public. 0 means present, 1 means absent, as in the wrapper.
    Group input validation is not silently sampled: the driver checks every pk.
    """
    L, u = pp.ctx.L, pp.ctx.u
    if (len(public_keys) != L or [p.slot for p in public_keys] != list(range(L))
            or len(profiles) != L
            or any(len(row) != u or any(type(b) is not int or b not in (0, 1)
                                       for b in row) for row in profiles)):
        raise ValueError("invalid roster/profile")
    T = a.g1_prod(p.T for p in public_keys)
    V = tuple(a.g2_prod(public_keys[j].V[i] for j in range(L) if j != i)
              for i in range(L))
    us, ws = [], []
    # Aggregate directly from the public absent lists; no artificial Y archive.
    # Reuse identical absent sets (common in the all-present main benchmark).
    cache = {}
    for w in range(u):
        absent = tuple(j for j in range(L) if profiles[j][w] == 1)
        if absent not in cache:
            uu = a.g1_prod(pp.U[j] for j in absent)
            ww = tuple(a.g2_prod(pp.W[pp.d[i]+pp.d[j]] for j in absent if i != j)
                       for i in range(L))
            cache[absent] = (uu, ww)
        uu, ww = cache[absent]
        us.append(uu)
        ws.append(ww)
    return Aggregate(pp, T, V, tuple(us), tuple(ws), tuple(map(tuple, profiles)))


@dataclass(frozen=True)
class Ciphertext:
    policy: Any
    C1: Any
    C2: Any
    C3: tuple
    C4: tuple
    C5: Any


def encrypt(agg, policy, message):
    policy.validate(a.P, agg.pp.ctx.u)
    a.member_gt(message)
    pp = agg.pp
    for p in (pp.g1, pp.h, agg.T):
        a.member_g1(p)
    for w in set(policy.rho):
        a.member_g1(agg.U[w])
    return encrypt_math(pp.g1, pp.h, pp.Omega, agg.T, agg.U, policy, message)


def encrypt_math(g, h, omega, T, U, policy, message):
    """Source ciphertext equations, also usable for wrapper arithmetic controls."""
    s = a.rand_scalar()
    h1 = a.g1_pow(g, a.rand_scalar())
    h2 = a.g1_div(h, h1)
    v = [1]+[a.rand_scalar() for _ in range(len(policy.matrix[0])-1)]
    c3, c4 = [], []
    for row, w in zip(policy.matrix, policy.rho):
        sk = a.rand_scalar()
        share = s*sum(x*v[j] for j,x in enumerate(row) if x) % a.P
        c3.append(a.double_scalar(h2,share,U[w],-sk))
        c4.append(a.g1_pow(g, sk))
    return Ciphertext(policy, message*omega**s, a.g1_pow(g, s), tuple(c3),
                      tuple(c4), a.g1_pow(a.g1_div(h1, T), s))


class User:
    def __init__(self, agg, secret):
        self.agg, self.secret = agg, secret
        self.slot = secret.slot
        self._reconstruction = {}
        pp = agg.pp
        for p in (pp.A[self.slot], pp.B[self.slot], agg.V[self.slot]):
            a.member_g2(p)
        self.fixed_factor = a.g2_div(a.g2_prod([
            a.g2_pow(pp.A[self.slot], secret.zeta), agg.V[self.slot]]), pp.B[self.slot])

    def selected(self, policy):
        policy.validate(a.P, self.agg.pp.ctx.u)
        key = policy.wire()
        if key not in self._reconstruction:
            try:
                self._reconstruction[key] = tuple(reconstruct(policy,
                    {w for w, b in enumerate(self.agg.profiles[self.slot]) if b == 0}, a.P))
            except ValueError as exc:
                raise a.UnsatisfiedPolicy(str(exc)) from exc
        return self._reconstruction[key]

    def decrypt(self, ct, *, optimized=True):
        pp, i = self.agg.pp, self.slot
        ct.policy.validate(a.P, pp.ctx.u)
        if len(ct.C3) != len(ct.policy.rho) or len(ct.C4) != len(ct.C3):
            raise ValueError("ciphertext shape")
        a.member_gt(ct.C1)
        for p in (ct.C2, ct.C5)+ct.C3+ct.C4:
            a.member_g1(p)
        weights = self.selected(ct.policy)
        labels = {ct.policy.rho[k] for k, x in enumerate(weights) if x}
        for w in labels:
            a.member_g2(self.agg.W[w][i])
        if not optimized:
            value = a.gt_pair(ct.C5, pp.A[i])*a.gt_pair(ct.C2, self.fixed_factor)
            for k, x in enumerate(weights):
                if x:
                    value *= (a.gt_pair(ct.C3[k], pp.A[i]) *
                              a.gt_pair(ct.C4[k], self.agg.W[ct.policy.rho[k]][i]))**x
            return ct.C1*value
        # Same bilinear grouping and multi-pairing backend as the v0.7 wrapper.
        same_A = a.g1_prod([ct.C5]+[a.g1_pow(p, x) for p, x in zip(ct.C3, weights) if x])
        grouped = {w: [] for w in labels}
        for k, x in enumerate(weights):
            if x:
                grouped[ct.policy.rho[k]].append(a.g1_pow(ct.C4[k], x))
        terms = [(same_A, pp.A[i]), (ct.C2, self.fixed_factor)]
        terms += [(a.g1_prod(grouped[w]), self.agg.W[w][i]) for w in sorted(labels)]
        return ct.C1*a.pair_product(terms)
