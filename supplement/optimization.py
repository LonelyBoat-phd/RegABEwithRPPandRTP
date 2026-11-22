"""Serial optimization choices; all global Y weights stay fresh and private."""
import json
from pathlib import Path
from regabe import primitives as a
from regabe.metrics import measure

_CONFIG = json.loads(Path(__file__).with_name('optimization-config.json').read_text())
def options():return dict(_CONFIG)

def proof_pair(sp, base, n, point, m):
    if _CONFIG['proof'] == 'fixed':
        tg, th, _ = a._registration_tables(sp)
        table = th if base == sp.H0 else tg
        return a.g1_prod([table.multiply(n), a.g1_pow(point, m)])
    return a.double_scalar(base,n,point,m)

def msm(points, scalars):
    n=len(points)
    selected=_CONFIG.get('windows',{})
    width=selected.get(str(n))
    if width is None:
        # Reuse only nearby calibration sizes; avoid oversized buckets on small MSMs.
        eligible=[int(k) for k in selected if n<=int(k)<=n*1.15]
        width=selected[str(min(eligible))] if eligible else None
    return a.GROUP.msm(points,scalars,width=width)

def global_round(sp, regs, method='auto', metrics=None):
    """One independent nonzero coefficient per original off-diagonal relation.

    This private helper requires the caller's pinned, fully checked snapshot.
    Merging right-hand MSMs preserves exactly the same weighted equation.
    """
    if method not in ('auto','native','pippenger','naive'):raise ValueError('MSM method')
    terms=[];rhs=[];all_y=[];all_weights=[]
    for i in range(sp.ctx.L):
        xs=[];ys=[];weights=[]
        for j,reg in enumerate(regs):
            if i==j:continue
            xs.extend(reg.X);ys.extend(reg.Y[i,j])
            weights.extend(measure(metrics, 'Y_weights_s', lambda:
                [a.secrets.randbelow(a.P-1)+1 for _ in range(sp.ctx.u)]))
        calc=lambda p,s: a._prime_order_msm(p,s,'G1','naive') if method=='naive' else msm(p,s)
        terms.append((measure(metrics, 'Y_msm_s', lambda: calc(xs,weights)),sp.A[i]))
        if _CONFIG['y_layout']=='merged':
            all_y.extend(ys);all_weights.extend(weights)
        else:rhs.append(measure(metrics, 'Y_msm_s', lambda: calc(ys,weights)))
    if _CONFIG['y_layout']=='merged':rhs=[measure(metrics, 'Y_msm_s', lambda: calc(all_y,all_weights))]
    terms.append((a.neg(sp.g1),a.g2_prod(rhs)))
    return measure(metrics, 'Y_pairing_s', lambda: a.pair_product(terms)==a.FQ12.one())
