"""Explicit experimental controls and compact private registration.

P: certified public registration + authenticated public-target withdrawal.
R: compact private registration + authenticated public-target withdrawal.
F: same private registration + original target-private update/client algorithms.
Research wire format, not a claim of deployment interoperability.
"""
from copy import deepcopy
from dataclasses import dataclass, replace
from time import perf_counter
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from regabe import primitives as a, core as c
from .optimization import global_round as _global_round, proof_pair
from regabe.validation import individual_round_validated
from regabe.metrics import stage, account


def measure(metrics, name, fn):
    start = perf_counter()
    result = fn()
    metrics[name] = metrics.get(name, 0.0) + perf_counter() - start
    return result


source_wire = a.registration_source_wire
PrivateRecord = a.Registration


def verify_certificate(sp, pk, cert, obj):
    c.check(cert.identity == pk.slot, 'certificate identity')
    try:
        a.verify_registration_certificate(sp, pk, cert, obj)
    except a.InvalidCertificate as exc:
        raise c.ProtocolError(str(exc)) from exc


@dataclass(frozen=True)
class PublicRecord:
    slot: int
    source_public: object
    bits: tuple
    cert: object

    def wire(self, sp):
        return c.seq([b'SUPPLEMENT-PUBLIC-v1', sp.ctx.pp_id, sp.ctx.schema_id,
                      source_wire(self.source_public), bytes(self.bits),
                      self.cert.message(), self.cert.signature])


def generate_public(sp, issuer, secret, pk, bits, metrics=None):
    c.check(len(bits) == sp.ctx.u and all(type(b) is int and b in (0, 1) for b in bits), 'bits')
    cert = measure(metrics if metrics is not None else {}, 'gen_certificate_s',
                   lambda: a.registration_certificate(sp, issuer, pk.slot, pk, bytes(bits)))
    return PublicRecord(pk.slot, pk, tuple(bits), cert)


def generate_private(sp, issuer, secret, pk, bits, metrics=None):
    # Local certificate issuance only; no ACA evidence/opening review service.
    enrollment = a._generate_compact_registration(sp, issuer, pk.slot, bits, secret, pk, metrics=metrics)
    return enrollment.public, enrollment.witness


def verify_record(sp, rec, source_receipt, metrics=None):
    metrics = {} if metrics is None else metrics
    c.check(type(rec.slot) is int and 0 <= rec.slot < sp.ctx.L and rec.source_public.slot == rec.slot,
            'record slot')
    if isinstance(rec, PublicRecord):
        measure(metrics, 'record_source_s',
                lambda: c.check(a._source_valid_or_receipt(sp, rec.source_public, source_receipt),
                                'source validity receipt'))
        c.check(len(rec.bits) == sp.ctx.u and all(type(b) is int and b in (0, 1) for b in rec.bits), 'public profile')
        measure(metrics, 'record_certificate_s',
                lambda: verify_certificate(sp, rec.source_public, rec.cert, bytes(rec.bits)))
        return
    c.check(isinstance(rec, PrivateRecord), 'private record type')
    c.check(rec.certificate.identity == rec.slot, 'certificate identity')
    try:
        a.verify_registration(sp, rec, source_receipt=source_receipt, metrics=metrics,
                              proof_pair=lambda base, n, point, m: proof_pair(sp, base, n, point, m))
    except (a.InvalidProof, a.InvalidCertificate) as exc:
        raise c.ProtocolError(str(exc)) from exc


def aggregate(sp, records, receipts, metrics, *, y_verifier='global'):
    """Full object-level admission; optional deterministic read-only reference.

    receipts=None performs all source checks inside this operation. The
    individual variant is an experimental reference, never the Full runtime's
    main admission or a retry after a failed global check.
    """
    c.check(y_verifier in ('global', 'individual'), 'Y verifier')
    c.check(receipts is None or len(receipts) == sp.ctx.L, 'source receipt count')
    def pin():
        regs = deepcopy(tuple(records))
        c.check(len(regs) == sp.ctx.L and tuple(r.slot for r in regs) == tuple(range(sp.ctx.L)), 'complete snapshot')
        return regs
    regs = measure(metrics, 'snapshot_s', pin)
    detail = {}
    measure(metrics, 'record_verify_s', lambda: [verify_record(sp, r, None if receipts is None else receipts[i], detail) for i, r in enumerate(regs)])
    metrics.update(detail)
    private = isinstance(regs[0], PrivateRecord)
    c.check(all(isinstance(r, PrivateRecord) == private for r in regs), 'mixed record types')
    if private:
        def members():
            for A in sp.A:
                c.check(not a.is_inf(A), 'nonidentity A')
            a.member_many((*sp.A, *(y for reg in regs for ys in reg.Y.values() for y in ys)))
        measure(metrics, 'Y_membership_s', members)
        y_detail = {}
        def single_y():
            if y_verifier == 'global':
                c.check(_global_round(sp, regs, 'auto', metrics=y_detail), 'one global Y check')
            else:
                c.check(individual_round_validated(sp, regs), 'individual Y reference')
        measure(metrics, 'Y_global_s' if y_verifier == 'global' else 'Y_individual_s', single_y)
        metrics.update(y_detail)
    def products():
        U, W = [], []
        cache = {}
        for w in range(sp.ctx.u):
            if private:
                U.append(a.g1_prod(r.X[w] for r in regs))
                W.append(tuple(a.g2_prod(regs[j].Y[i, j][w] for j in range(sp.ctx.L) if i != j)
                               for i in range(sp.ctx.L)))
            else:
                absent = tuple(j for j in range(sp.ctx.L) if regs[j].bits[w] == 1)
                if absent not in cache:
                    cache[absent] = (a.g1_prod(sp.U[j] for j in absent),
                                    tuple(a.g2_prod(sp.W[i, j] for j in absent if i != j) for i in range(sp.ctx.L)))
                uu, ww = cache[absent]
                U.append(uu); W.append(ww)
        T = a.g1_prod(r.source_public.T for r in regs)
        V = tuple(a.g2_prod(regs[j].source_public.V[i] for j in range(sp.ctx.L) if i != j)
                  for i in range(sp.ctx.L))
        return U, W, T, V
    U, W, T, V = measure(metrics, 'products_s', products)
    def roots():
        meta = c.Meta(sp.ctx.pp_id, sp.ctx.sid, sp.ctx.ctx_id, sp.ctx.L, sp.ctx.u)
        fixed = [c.UserPublic(i, sp.A[i], sp.B[i], V[i], sp.U[i], c.Path(0, 1, ())) for i in range(sp.ctx.L)]
        tree = c.Tree(c.domain(meta, b'FIXED'), [c.fixed_leaf(x) for x in fixed])
        fixed = tuple(replace(x, path=tree.path(i)) for i, x in enumerate(fixed))
        public = c.PublicParameters(meta, sp.g1, sp.h, sp.Omega, T, tree.root)
        blocks = [c.make_block(meta, w, 0, U[w], W[w]) for w in range(sp.ctx.u)]
        return public, c.make_state(meta, blocks), fixed
    return measure(metrics, 'authenticated_state_s', roots)


@dataclass(frozen=True)
class Notice:
    event: object
    target: int
    old_descriptor: bytes
    new_descriptor: bytes
    head: object = None
    ra_signature: bytes = b''

    def body(self):
        return c.seq([b'SUPPLEMENT-PUBLIC-TARGET-v1', self.event.wire(), a.i2b(self.target, 4),
                      self.old_descriptor, self.new_descriptor])

    @property
    def digest(self):
        return a.sha256(b'PUBLIC-TARGET-NOTICE', self.body())

    def canonical(self):
        return c.seq([self.body(), self.head.wire(), self.ra_signature])


class PublicRA:
    def __init__(self, sp, profiles):
        self.sp = sp
        self.meta = c.Meta(sp.ctx.pp_id, sp.ctx.sid, sp.ctx.ctx_id, sp.ctx.L, sp.ctx.u)
        self._bits = [list(row) for row in profiles]
        self._signer = Ed25519PrivateKey.generate()
        self.verification_key = self._signer.public_key().public_bytes_raw()
        self._head = None; self._nonces = set(); self._pending = {}

    def endorse_genesis(self, head):
        c.check(self._head is None and head.meta == self.meta and head.version == 0, 'genesis')
        self._head = head.digest
        return self._signer.sign(head.wire())

    def prepare(self, kc, target, attr, *, metrics=None):
        with stage(metrics, 'proposal_material_s'):
            parent, block = kc.revocation_material(attr)
        with stage(metrics, 'ra_checks_s'):
            c.check(parent.digest == self._head and 0 <= target < self.meta.L and 0 <= attr < self.meta.u, 'public target/parent')
            c.check(self._bits[target][attr] == 0, 'active target')
            nonce = secrets.token_bytes(64)
            c.check(nonce not in self._nonces, 'nonce collision')
            self._nonces.add(nonce)
            evt = c.Event(self.meta, attr, parent.digest, parent.version, parent.version + 1,
                          block.descriptor.counter, block.descriptor.counter + 1, nonce)
        nb = public_next_block(self.sp, block, target, metrics=metrics, prefix='ra')
        with stage(metrics, 'ra_head_auth_s'):
            notice = Notice(evt, target, block.descriptor.wire(), nb.descriptor.wire())
            old_cell = c.Cell(block.descriptor, kc._state.tree.path(attr))
            c.validate_cell(self.meta, parent, old_cell)
            root = c.path_root(c.domain(self.meta, b'ATTR'), nb.descriptor.wire(), old_cell.path)
            head = c.Head(self.meta, evt.new_version, parent.digest, parent.base, root, evt.digest, notice.digest)
            notice = replace(notice, head=head, ra_signature=self._signer.sign(head.wire()))
            self._pending[notice.digest] = notice
            return notice

    def accept_commit(self, receipt, trust):
        c.authenticate(receipt.head, receipt.auth, trust)
        c.check(receipt.head.parent == self._head, 'RA commit parent')
        notice = self._pending[receipt.head.manifest]
        c.check(receipt.head.digest == notice.head.digest, 'RA exact proposal')
        self._bits[notice.target][notice.event.attr] = 1
        self._head = receipt.head.digest; self._pending.clear()


def public_next_block(sp, block, target, *, metrics=None, prefix='ra'):
    with stage(metrics, prefix + '_successor_arithmetic_s'):
        w = block.descriptor.attr
        helpers = [h if i == target else a.g2_prod([h, sp.W[i, target]]) for i, h in enumerate(block.helpers)]
        next_u = a.g1_prod([block.descriptor.U, sp.U[target]])
        meta = c.Meta(sp.ctx.pp_id, sp.ctx.sid, sp.ctx.ctx_id, sp.ctx.L, sp.ctx.u)
    with stage(metrics, prefix + '_helper_tree_s'):
        return c.make_block(meta, w, block.descriptor.counter + 1, next_u, helpers)


@dataclass(frozen=True)
class PublicSync:
    notice: object
    commit: object

    def wire(self):
        return c.seq([self.notice.body(), receipt_wire(self.commit)])


def receipt_wire(commit):
    return c.seq([commit.head.wire(), commit.auth.ra, commit.auth.kc, commit.auth.board])


def full_sync_wire(material):
    def path(p):
        return c.seq([a.i2b(p.index, 4), a.i2b(p.count, 4), *p.siblings])
    return c.seq([material.manifest.wire(), receipt_wire(material.commit), a.pbytes_g1(material.du),
                  a.pbytes_g2(material.own_delta), path(material.common_path), path(material.own_path)])


class PublicKC(c.KC):
    def __init__(self, sp, public, state, fixed, ra_key):
        super().__init__(public.meta, public, state, fixed, ra_key)
        self.sp = sp

    def prepare_with(self, ra, target, attr, *, metrics=None):
        return ra.prepare(self, target, attr, metrics=metrics)

    def validate(self, packet, *, metrics=None):
        with stage(metrics, 'kc_snapshot_s'):
            p = deepcopy(packet); evt = p.event; old = self._head; head = p.head
        with stage(metrics, 'kc_signature_s'):
            c.verify(self.ra_key, p.ra_signature, head.wire())
        with stage(metrics, 'kc_checks_s'):
            c.check(evt.meta == self.meta and head.meta == self.meta and 0 <= p.target < self.meta.L, 'notice context/target')
            c.check(evt.parent == head.parent == old.digest and evt.old_version == old.version
                    and evt.new_version == head.version == old.version + 1, 'notice parent/version')
            c.check(0 <= evt.attr < self.meta.u and isinstance(evt.nonce, bytes) and len(evt.nonce) == 64, 'notice event')
            block = self._state.blocks[evt.attr]
            c.check(evt.old_counter == block.descriptor.counter and evt.new_counter == evt.old_counter + 1, 'counter')
        nb = public_next_block(self.sp, block, p.target, metrics=metrics, prefix='kc')
        with stage(metrics, 'kc_descriptor_checks_s'):
            c.check(p.old_descriptor == block.descriptor.wire() and p.new_descriptor == nb.descriptor.wire(), 'notice descriptors')
        with stage(metrics, 'kc_attribute_state_s'):
            state = c.replace_block(self.meta, self._state, evt.attr, nb)
        with stage(metrics, 'kc_head_checks_s'):
            c.check(head.root == state.tree.root and head.base == old.base and head.event == evt.digest
                    and head.manifest == p.digest, 'notice head bindings')
        with stage(metrics, 'kc_sign_stage_s'):
            token = secrets.token_bytes(32)
            self._prepared[token] = (old.digest, p, state, self._signer.sign(head.wire()))
            return c.Prepared(token)

    def commit(self, board, prepared):
        c.check(isinstance(prepared, c.Prepared) and prepared.token in self._prepared, 'prepared token')
        parent, p, state, sig = self._prepared[prepared.token]
        c.check(parent == self._head.digest == board.latest.head.digest, 'commit CAS')
        receipt = board.append(p.head, p.ra_signature, sig)
        self._state = state; self._head = p.head; self._history[p.head.digest] = state
        self._sync[p.head.digest] = PublicSync(p, receipt)
        self._prepared.clear()
        return receipt

    def sync_input(self, slot, head_digest):
        c.check(0 <= slot < self.meta.L and head_digest in self._sync, 'sync request')
        return deepcopy(self._sync[head_digest])


class PublicTargetUser(c.User):
    def catch_up(self, material, *, metrics=None):
        with stage(metrics, 'client_input_s'):
            c.check(isinstance(material, PublicSync), 'public sync type')
            p, commit = material.notice, material.commit
            evt = p.event
        with stage(metrics, 'client_auth_s'):
            c.authenticate(commit.head, commit.auth, self.trust)
        with stage(metrics, 'client_bindings_s'):
            c.check(p.head == commit.head and commit.head.manifest == p.digest
                    and commit.head.event == evt.digest and evt.meta == self.public.meta, 'signed target binding')
            c.check(0 <= p.target < self.public.meta.L and 0 <= evt.attr < self.public.meta.u
                    and isinstance(evt.nonce, bytes) and len(evt.nonce) == 64, 'notice shape')
        with stage(metrics, 'client_progression_s'):
            if commit.head.digest in self._receipts:
                return False
            c.check(evt.parent == commit.head.parent == self.head and evt.old_version == self.version
                    and evt.new_version == commit.head.version == self.version + 1
                    and evt.old_counter == self._counters[evt.attr]
                    and evt.new_counter == evt.old_counter + 1, 'public sync progression')
        with stage(metrics, 'client_state_s'):
            bits, counters = list(self._bits), list(self._counters)
            if p.target == self.slot:
                c.check(bits[evt.attr] == 0, 'already revoked')
                bits[evt.attr] = 1; self._reconstruction.clear()
            counters[evt.attr] += 1
            self._bits, self._counters = tuple(bits), tuple(counters)
            self.head, self.version = commit.head.digest, commit.head.version
            self._receipts.add(self.head); self._wloc_cache.clear()
            return True



def runtime(sp, profiles, aggregate_result, secrets_, witnesses, scheme, metrics=None, slots=(0, 1)):
    metrics = {} if metrics is None else metrics
    public, state, fixed = aggregate_result
    ra = measure(metrics, 'authority_initialize_s', lambda: c.RA(sp, profiles) if scheme == 'F' else PublicRA(sp, profiles))
    kc = c.KC(public.meta, public, state, fixed, ra.verification_key) if scheme == 'F' else PublicKC(sp, public, state, fixed, ra.verification_key)
    board = c.Board(public.meta, ra.verification_key, kc.verification_key)
    genesis = kc.genesis(ra, board)
    users = {}
    for i in slots:
        key = ra.deliver_own_key(i) if scheme == 'F' else b''
        cls = c.User if scheme == 'F' else PublicTargetUser
        users[i] = cls(public, fixed[i], secrets_[i], witnesses[i], key, genesis, board.trust)
    return ra, kc, board, users


def revoke(rt, target, attr, metrics):
    ra, kc, board, _ = rt
    packet = measure(metrics, 'revoke_prepare_s', lambda: kc.prepare_with(ra, target, attr, metrics=metrics))
    token = measure(metrics, 'update_validate_s', lambda: kc.validate(packet, metrics=metrics))
    account(metrics, 'revoke_prepare_s', ('ra_', 'proposal_'), 'revoke_unattributed_s')
    account(metrics, 'update_validate_s', ('kc_',), 'update_unattributed_s')
    def install():
        receipt = kc.commit(board, token)
        ra.accept_commit(receipt, board.trust)
        return receipt
    receipt = measure(metrics, 'commit_install_s', install)
    return packet, receipt
