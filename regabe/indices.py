"""Compact positive progression-free, double-free ternary indices."""
def compact_set(L):
    if type(L) is not int or L<2:raise ValueError('L >= 2')
    return tuple(2*sum(((j>>k)&1)*3**k for k in range(j.bit_length()))+1 for j in range(L))

def unique_sums(d):return tuple(sorted({x+y for i,x in enumerate(d) for y in d[i+1:]}))
