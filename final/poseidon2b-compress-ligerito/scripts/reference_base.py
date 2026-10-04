#!/usr/bin/env python3
"""Independent scalar GHASH-basis reference and deterministic test vectors.

Round/constant/matrix recipes: Poseidon2b paper §3.2 / App. B and the authors'
Sage reference at revision 7072a9438cf48f1b38ad0092cda5452626914068.
No Flock or Rust code is invoked. TurboSHAKE256 uses Keccak-p[1600,12].
The Sage implementation explicitly accepts an irreducible polynomial argument;
here it is X^128 + X^7 + X^2 + X + 1, matching Flock's field representation.
"""
MASK=(1<<64)-1
RC=[0x1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
RHO=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
def rol(v,n):return ((v<<n)|(v>>(64-n)))&MASK if n else v

def keccak_p(a):
 for rc in RC[12:]:
  c=[a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20] for x in range(5)]
  d=[c[(x-1)%5]^rol(c[(x+1)%5],1) for x in range(5)]
  a=[v^d[i%5] for i,v in enumerate(a)]
  b=[0]*25
  for x in range(5):
   for y in range(5):b[y+5*((2*x+3*y)%5)]=rol(a[x+5*y],RHO[x][y])
  a=[b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]) for y in range(5) for x in range(5)]
  a[0]^=rc
 return a

def shake_stream(message):
 rate=136;block=bytearray(rate);block[:len(message)]=message;block[len(message)]^=0x1f;block[-1]^=0x80
 state=[int.from_bytes(block[8*i:8*i+8],'little') for i in range(17)]+[0]*8
 while True:
  state=keccak_p(state)
  yield from b''.join(x.to_bytes(8,'little') for x in state[:17])

MOD=(1<<128)|0x87
def mul(a,b):
 out=0
 while b:
  if b&1:out^=a
  b>>=1;a<<=1
  if a>>128:a^=MOD
 return out

def power(x,n):
 out=1
 while n:
  if n&1:out=mul(out,x)
  x=mul(x,x);n>>=1
 return out
def xor(values):
 out=0
 for x in values:out^=x
 return out

