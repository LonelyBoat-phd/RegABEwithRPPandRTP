"""Matrix LSSS with row-first RREF; canonical coefficients, repeated labels allowed."""
from dataclasses import dataclass
from functools import lru_cache
import json

@lru_cache(maxsize=256)
def canonical_policy(matrix,rho):
    return json.dumps({'matrix':matrix,'rho':rho},sort_keys=True,separators=(',',':')).encode()

@dataclass(frozen=True)
class Policy:
    matrix: tuple
    rho: tuple
    def __post_init__(self):
        object.__setattr__(self,'matrix',tuple(tuple(row) for row in self.matrix))
        object.__setattr__(self,'rho',tuple(self.rho))
    def validate(self,p,attributes=None):
        if not self.matrix or len(self.matrix)!=len(self.rho) or not self.matrix[0]: raise ValueError('empty/mismatched policy')
        for row,label in zip(self.matrix,self.rho):
            if len(row)!=len(self.matrix[0]) or any(type(x)!=int or not 0<=x<p for x in row): raise ValueError('ragged/noncanonical matrix')
            if type(label)!=int or label<0 or (attributes is not None and label>=attributes): raise ValueError('unknown label')
    def wire(self):
        return canonical_policy(self.matrix,self.rho)

def reconstruct(policy,attributes,p):
    policy.validate(p)
    selected=[k for k,label in enumerate(policy.rho) if label in attributes]
    if not selected: raise ValueError('unsatisfied policy')
    n=len(selected); d=len(policy.matrix[0])
    a=[[policy.matrix[k][j] for k in selected]+[int(j==0)] for j in range(d)]
    pivots=[]; r=0
    for c in range(n):
        pivot=next((i for i in range(r,d) if a[i][c]),None)
        if pivot is None: continue
        a[r],a[pivot]=a[pivot],a[r]; inv=pow(a[r][c],-1,p); a[r]=[x*inv%p for x in a[r]]
        for i in range(d):
            if i!=r:
                q=a[i][c]; a[i]=[(x-q*y)%p for x,y in zip(a[i],a[r])]
        pivots.append(c); r+=1
        if r==d: break
    if any(not any(row[:n]) and row[n] for row in a): raise ValueError('unsatisfied policy')
    sol=[0]*n
    for i,c in enumerate(pivots): sol[c]=a[i][n]
    out=[0]*len(policy.rho)
    for k,x in zip(selected,sol): out[k]=x
    if any(sum(out[k]*policy.matrix[k][j] for k in range(len(out)))%p!=int(j==0) for j in range(d)): raise ValueError('reconstruction invariant')
    return out


def all_attributes_and(attributes, p):
    """All distinct supplied labels are required; sum of rows is e_1."""
    labels=tuple(attributes)
    if not labels or len(set(labels))!=len(labels) or any(type(x)!=int or x<0 for x in labels):
        raise ValueError("nonempty distinct nonnegative labels required")
    n=len(labels)
    if n==1: return Policy([[1]],labels)
    rows=[]
    for i in range(n):
        row=[0]*n
        if i==0: row[0]=1;row[1]=1
        else:
            row[i]=p-1
            if i+1<n:row[i+1]=1
        rows.append(row)
    policy=Policy(rows,labels);policy.validate(p)
    return policy
