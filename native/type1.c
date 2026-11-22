#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <gmp.h>
#include "pbc.h"

/* PBC Type A only. All exported elements are owned by Python wrappers.
 * Operations allocate new elements: published Python values are immutable.
 * This is a serial, variable-time research backend, not a hardened service. */
typedef struct { pairing_t pairing; size_t refs; } ctx_t;
typedef struct { ctx_t *ctx; int kind; element_t e; } val_t;
typedef struct { val_t *base; ctx_t *ctx; element_pp_t table; } table_t;
static void release(ctx_t*c){if(!--c->refs){pairing_clear(c->pairing);free(c);}}
static void scalar(mpz_t x, const char *s) { mpz_init_set_str(x,s,16); }
const char *ra_gmp_version(void){return gmp_version;}
int ra_prime(const char*s){mpz_t n;scalar(n,s);int ok=mpz_probab_prime_p(n,50);mpz_clear(n);return ok;}
static val_t *fresh(ctx_t *c,int kind) {
  val_t *v=malloc(sizeof(*v)); v->ctx=c; v->kind=kind;c->refs++;
  if(kind==0) element_init_G1(v->e,c->pairing);
  else element_init_GT(v->e,c->pairing);
  return v;
}
void *ra_ctx(const char *params) {
  ctx_t *c=malloc(sizeof(*c));c->refs=1;
  if(pairing_init_set_buf(c->pairing,params,strlen(params))) {free(c);return NULL;}
  if(!pairing_is_symmetric(c->pairing)){pairing_clear(c->pairing);free(c);return NULL;}
  return c;
}
void ra_ctx_free(void *p){release(p);}
void ra_free(void *p){val_t*v=p;ctx_t*c=v->ctx;element_clear(v->e);free(v);release(c);}
void *ra_identity(void *p,int kind){val_t*v=fresh(p,kind);element_set1(v->e);return v;}
void *ra_hash(void *p,const unsigned char *data,int n){
  val_t*v=fresh(p,0);element_from_hash(v->e,(void*)data,n);return v;
}
void *ra_mul(void *xp,void *yp){val_t*x=xp,*y=yp,*z=fresh(x->ctx,x->kind);element_mul(z->e,x->e,y->e);return z;}
void *ra_inv(void *xp){val_t*x=xp,*z=fresh(x->ctx,x->kind);element_invert(z->e,x->e);return z;}
void *ra_pow(void *xp,const char *n){
  val_t*x=xp,*z=fresh(x->ctx,x->kind);mpz_t k;scalar(k,n);
  element_pow_mpz(z->e,x->e,k);mpz_clear(k);return z;
}
void *ra_pow2(void *xp,const char *ns,void *yp,const char *ms){
  val_t*x=xp,*y=yp,*z=fresh(x->ctx,x->kind);mpz_t n,m;scalar(n,ns);scalar(m,ms);
  element_pow2_mpz(z->e,x->e,n,y->e,m);mpz_clear(n);mpz_clear(m);return z;
}
int ra_equal(void *xp,void *yp){return !element_cmp(((val_t*)xp)->e,((val_t*)yp)->e);}
int ra_unit(void *xp){return element_is1(((val_t*)xp)->e);}
int ra_length(void *xp){return element_length_in_bytes(((val_t*)xp)->e);}
int ra_encode(unsigned char *out,void *xp){return element_to_bytes(out,((val_t*)xp)->e);}
void *ra_decode(void *cp,int kind,const unsigned char *data){
  val_t*v=fresh(cp,kind);element_from_bytes(v->e,(unsigned char*)data);return v;
}
int ra_curve(void *xp,const char *qs){
  val_t*x=xp;if(x->kind)return 0;if(element_is1(x->e))return 1;
  mpz_t q,a,b,lhs,rhs;scalar(q,qs);mpz_inits(a,b,lhs,rhs,NULL);
  element_to_mpz(a,element_x(x->e));element_to_mpz(b,element_y(x->e));
  int ok=mpz_sgn(a)>=0&&mpz_cmp(a,q)<0&&mpz_sgn(b)>=0&&mpz_cmp(b,q)<0;
  mpz_mul(lhs,b,b);mpz_mod(lhs,lhs,q);
  mpz_mul(rhs,a,a);mpz_mul(rhs,rhs,a);mpz_add(rhs,rhs,a);mpz_mod(rhs,rhs,q);
  ok=ok&&!mpz_cmp(lhs,rhs);mpz_clears(q,a,b,lhs,rhs,NULL);return ok;
}
void *ra_pair(void *xp,void *yp){
  val_t*x=xp,*y=yp,*z=fresh(x->ctx,1);pairing_apply(z->e,x->e,y->e,x->ctx->pairing);return z;
}
void *ra_pair_product(void *cp,void **xs,void **ys,int n){
  ctx_t*c=cp;val_t*z=fresh(c,1);element_set1(z->e);
  if(!n)return z;
  element_t *a=malloc(n*sizeof(element_t)),*b=malloc(n*sizeof(element_t));
  for(int i=0;i<n;i++){element_init_G1(a[i],c->pairing);element_init_G2(b[i],c->pairing);
    element_set(a[i],((val_t*)xs[i])->e);element_set(b[i],((val_t*)ys[i])->e);}
  element_prod_pairing(z->e,a,b,n);
  for(int i=0;i<n;i++){element_clear(a[i]);element_clear(b[i]);}free(a);free(b);return z;
}
void *ra_table(void *xp){table_t*t=malloc(sizeof(*t));t->base=xp;t->ctx=t->base->ctx;t->ctx->refs++;element_pp_init(t->table,((val_t*)xp)->e);return t;}
void ra_table_free(void *tp){table_t*t=tp;ctx_t*c=t->ctx;element_pp_clear(t->table);free(t);release(c);}
void *ra_table_pow(void *tp,const char *ns){
  table_t*t=tp;val_t*z=fresh(t->base->ctx,t->base->kind);mpz_t n;scalar(n,ns);
  element_pp_pow(z->e,n,t->table);mpz_clear(n);return z;
}
/* Native Pippenger. Source points have already passed membership checking. */
void *ra_msm(void *cp,void **points,const char **scalars,int n,int width){
  ctx_t*c=cp;val_t*out=fresh(c,0);element_set1(out->e);if(!n)return out;
  mpz_t *k=malloc(n*sizeof(mpz_t));int bits=0;
  for(int i=0;i<n;i++){scalar(k[i],scalars[i]);int b=mpz_sizeinbase(k[i],2);if(b>bits)bits=b;}
  int stride=(bits+7)/8+2;
  unsigned char *digits=calloc((size_t)n,stride);
  for(int i=0;i<n;i++){size_t written=0;mpz_export(digits+(size_t)i*stride,&written,-1,1,0,0,k[i]);}
  int count=1<<width;element_t*buckets=malloc(count*sizeof(element_t));element_t running;
  for(int j=0;j<count;j++)element_init_G1(buckets[j],c->pairing);
  element_init_G1(running,c->pairing);
  for(int shift=((bits-1)/width)*width;shift>=0;shift-=width){
    for(int j=0;j<width;j++)element_double(out->e,out->e);
    for(int j=0;j<count;j++)element_set1(buckets[j]);
    for(int i=0;i<n;i++){
      unsigned char *d=digits+(size_t)i*stride+shift/8;
      unsigned digit=((unsigned)d[0]|((unsigned)d[1]<<8)|((unsigned)d[2]<<16))>>(shift%8);
      digit&=(1u<<width)-1;
      if(digit)element_mul(buckets[digit],buckets[digit],((val_t*)points[i])->e);
    }
    element_set1(running);
    for(int j=count-1;j>0;j--){element_mul(running,running,buckets[j]);element_mul(out->e,out->e,running);}
  }
  for(int j=0;j<count;j++)element_clear(buckets[j]);element_clear(running);free(buckets);
  for(int i=0;i<n;i++)mpz_clear(k[i]);free(k);free(digits);return out;
}
char *ra_params(int rb,int qb){
  FILE*entropy=fopen("/dev/urandom","rb");if(!entropy)return NULL;fclose(entropy);
  pbc_param_t p;pbc_param_init_a_gen(p,rb,qb);char*out=NULL;size_t len=0;
  FILE*f=open_memstream(&out,&len);if(!f){pbc_param_clear(p);return NULL;}
  pbc_param_out_str(f,p);fclose(f);pbc_param_clear(p);return out;
}
void ra_string_free(void*p){free(p);}

/* Exact per-element tests, batched only to amortize FFI, scalar and scratch setup.
 * Return -1 on success; otherwise return the first invalid coordinate. */
int ra_member_many(void *cp, void **points, int n, const char *qs, const char *rs) {
  ctx_t *c=cp; mpz_t r; scalar(r,rs);
  element_t check; element_init_G1(check,c->pairing);
  for(int i=0;i<n;i++) {
    val_t *x=points[i];
    if(x->ctx!=c || x->kind!=0 || !ra_curve(x,qs)) {
      element_clear(check);mpz_clear(r);return i;
    }
    element_pow_mpz(check,x->e,r);
    if(!element_is1(check)){element_clear(check);mpz_clear(r);return i;}
  }
  element_clear(check);mpz_clear(r);return -1;
}
void *ra_product(void *cp, void **points, int n) {
  ctx_t *c=cp;val_t *out=fresh(c,0);element_set1(out->e);
  for(int i=0;i<n;i++)element_mul(out->e,out->e,((val_t*)points[i])->e);
  return out;
}
