"""Small real-pairing example: withdraw one attribute and retain old access."""
import regabe as r
from regabe import primitives as a

x=r.build(2,2,exclude_isvalid=True)
policy=r.all_attributes_and([0,1],a.P)
message=x.kc.public.omega**123
old_user=x.users[0].checkpoint()
sender=x.kc.sender_input(x.board,policy.rho)
ct=r.encrypt(sender,policy,message,x.board.trust,latest=x.board.latest)
old_material=x.kc.decrypt_input(x.board,0,old_user.labels(policy),ct.head)
assert old_user.decrypt(old_material,ct)==message
_,receipt=r.revoke(x,0,0)
for user in x.users:user.catch_up(x.kc.sync_input(user.slot,receipt.head.digest))
try:x.users[0].labels(policy)
except a.UnsatisfiedPolicy:print('Revoked user: new AND policy denied')
else:raise AssertionError('withdrawal did not take effect')
new_sender=x.kc.sender_input(x.board,policy.rho)
new_ct=r.encrypt(new_sender,policy,message,x.board.trust,latest=x.board.latest)
user=x.users[1]
assert user.decrypt(x.kc.decrypt_input(x.board,1,user.labels(policy),new_ct.head),new_ct)==message
assert old_user.decrypt(old_material,ct)==message
print('Unaffected user: new ciphertext decrypted')
print('Retained old user state: historical ciphertext decrypted')
