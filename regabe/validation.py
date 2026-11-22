"""One global weighted Y pass; diagnostics are opt-in.

All weights are private fresh uniform nonzero scalars, sampled AFTER pinning
and validating the whole snapshot. No weights or PRNG seeds are output.
One fixed erroneous prime-order snapshot passes one round with probability
at most 1/(r-1). This is not a claim of zero error or a complete system bound.
"""
from copy import deepcopy
from . import primitives as a

def individual_round_validated(sp, regs):
    """Internal read-only reference on the same pinned prime-order snapshot.

    The caller performs the complete shape and membership checks once, exactly
    as for the global round. This loop neither repeats them per relation nor
    supplies a new main-execution admission decision.
    """
    valid = True
    for i in range(sp.ctx.L):
        for j, reg in enumerate(regs):
            if i == j:
                continue
            for w in range(sp.ctx.u):
                result = a.pairing_equal(reg.X[w], sp.A[i], sp.g1, reg.Y[i, j][w])
                valid = bool(result) and valid  # evaluate every relation
    return valid

def _receiver_sums(sp,regs,i,method):
    xs=[];ys=[];weights=[]
    for j,reg in enumerate(regs):
        if i==j:continue
        xs.extend(reg.X);ys.extend(reg.Y[i,j])
        weights.extend(a.secrets.randbelow(a.P-1)+1 for _ in range(sp.ctx.u))
    return (a._prime_order_msm(xs,weights,'G1',method),
            a._prime_order_msm(ys,weights,'G2',method))

def _global_round(sp,regs,method):
    terms=[];rhs=[]
    for i in range(sp.ctx.L):
        x,y=_receiver_sums(sp,regs,i,method);terms.append((x,sp.A[i]));rhs.append(y)
    terms.append((a.neg(sp.g1),a.g2_prod(rhs)))
    return a.pair_product(terms)==a.FQ12.one()

def diagnose_snapshot(sp,regs,*,msm_method='auto'):
    """Fresh receiver -> submitter batches -> individual attribute relations.
    A failed global packet STAYS rejected even if diagnostics find no location.
    This function does not replace the initial global acceptance decision.
    """
    errors=[]
    for i in range(sp.ctx.L):
        x,y=_receiver_sums(sp,regs,i,msm_method)
        if a.pairing_equal(x,sp.A[i],sp.g1,y):continue
        before=len(errors)
        for j in range(sp.ctx.L):
            if i==j:continue
            try:a._batch_y_check_prime_order(sp,regs,i,j,locate=True,msm_method=msm_method)
            except a.BatchFailure as exc:errors.extend(exc.errors)
        if before==len(errors):errors.append((i,-1,-1))
    return errors or [(-1,-1,-1)]

def verify_all_y(sp,registrations,*,diagnose=False,msm_method='auto',progress=None,_checked_X=False):
    a._check_msm_method(msm_method)
    regs=tuple(registrations) if _checked_X else deepcopy(tuple(registrations))
    if len(regs)!=sp.ctx.L or tuple(r.slot for r in regs)!=tuple(range(sp.ctx.L)):
        raise a.InvalidY('roster')
    for i,base in enumerate(sp.A):
        a.member_g2(base)
        if a.is_inf(base):raise a.InvalidY('unit A')
    for j,reg in enumerate(regs):
        if len(reg.X)!=sp.ctx.u or set(reg.Y)!={(i,j) for i in range(sp.ctx.L) if i!=j}:
            raise a.InvalidY('Y/X shape')
        if not _checked_X:
            for x in reg.X:a.member_g1(x)
        for row in reg.Y.values():
            if len(row)!=sp.ctx.u:raise a.InvalidY('Y row')
            for y in row:a.member_g2(y)
    if progress:
        progress('KC: global randomized YCheck')
    if not _global_round(sp, regs, msm_method):
        errors = diagnose_snapshot(sp, regs, msm_method=msm_method) if diagnose else [(-1,-1,-1)]
        raise a.BatchFailure(errors)
    return True
