"""Experiment driver: role wiring is outside measured algorithm entrypoints."""
from dataclasses import dataclass
from . import primitives as a
from .core import RA,KC,Board,User,freeze

@dataclass
class Experiment:
    parameters: object
    ra: RA
    kc: KC
    board: Board
    users: tuple
    registrations: tuple
    enrollment_timings: dict


def build(L=2,u=2,profiles=None,timer=None,progress=None,*,batch_size=0,msm_method="auto",user_slots=None,correction_fixed_base=True,exclude_isvalid=False,diagnose=False):
    a.ycheck_batch_plan(L,u,batch_size);a._check_msm_method(msm_method)
    if type(correction_fixed_base)!=bool:raise ValueError('correction_fixed_base must be bool')
    slots=tuple(range(L)) if user_slots is None else tuple(user_slots)
    if not slots or len(set(slots))!=len(slots) or any(type(i)!=int or not 0<=i<L for i in slots):
        raise ValueError('nonempty unique user_slots within roster required')
    if profiles is None:profiles=tuple((0,)*u for _ in range(L))
    if timer is None:timer=lambda name,fn:fn()
    sp,issuer=timer('setup',lambda:a.setup(L,u));enrollments=[];secrets=[];receipts=[]
    for i in range(L):
        sec,pub=timer('source_keygen',lambda:a.source_keygen(sp,i));secrets.append(sec)
        receipt=a.validate_source(sp,pub) if exclude_isvalid else None
        receipts.append(receipt)
        if not exclude_isvalid:timer('source_validate',lambda:a.validate_source(sp,pub))
        e=timer('registration_generate_excluding_IsValid' if exclude_isvalid else 'registration_generate_with_IsValid',lambda:a.generate_registration(sp,issuer,i,profiles[i],sec,pub,source_receipt=receipt))
        enrollments.append(e)
    # Public records, not user witnesses, are given to the public aggregate.
    regs=tuple(e.public for e in enrollments)
    public,state,fixed=timer('freeze_with_admission_checks',lambda:freeze(sp,regs,progress=progress,batch_size=batch_size,msm_method=msm_method,source_receipts=receipts if exclude_isvalid else None,diagnose=diagnose))
    ra=timer('RA_private_initialize',lambda:RA(sp,profiles,fixed_base=correction_fixed_base));kc=KC(ra.meta,public,state,fixed,ra.verification_key);board=Board(ra.meta,ra.verification_key,kc.verification_key)
    genesis=timer('genesis_commit',lambda:kc.genesis(ra,board))
    users=tuple(timer('user_initialize_with_cache',lambda:User(public,fixed[i],secrets[i],enrollments[i].witness,ra.deliver_own_key(i),genesis,board.trust)) for i in slots)
    return Experiment(sp,ra,kc,board,users,regs,{})


def revoke(experiment,target,attr,timer=None):
    if timer is None:timer=lambda name,fn:fn()
    packet=timer('revoke_prepare',lambda:experiment.kc.prepare_with(experiment.ra,target,attr))
    checked=timer('update_validate_and_nextstate',lambda:experiment.kc.validate(packet))
    receipt=timer('commit_reuse_checked_state',lambda:experiment.kc.commit(experiment.board,checked))
    experiment.ra.accept_commit(receipt,experiment.board.trust)
    return packet,receipt
