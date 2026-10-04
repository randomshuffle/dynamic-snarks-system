#!/usr/bin/env python3
"""Independent n=128,t=4 Poseidon2b compression vectors (paper §3.1.2).

Uses the independent Python GF128/TurboSHAKE primitives in reference_base.py. No Rust/Flock code or Rust-generated constants are used.
"""
from pathlib import Path
import json
import runpy

base = Path(__file__).resolve().parent / 'reference_base.py'
ref = runpy.run_path(str(base))
mul, power, xor = (ref[k] for k in ['mul', 'power', 'xor'])
M = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]]
DIAG = [1 << 5, 1 << 13, 1 << 9, 1 << 11]


def constants():
    stream = ref['shake_stream'](b'Poseidon2b' + bytes(16) + (1).to_bytes(8, 'little'))
    out = []
    while len(out) < 264:
        candidate = bytes(next(stream) for _ in range(17))
        if candidate[16] == 0:
            out.append(int.from_bytes(candidate[:16], 'little'))
    return [out[4*i:4*i+4] for i in range(66)]


def external(s):
    return [xor(mul(c, x) for c, x in zip(row, s)) for row in M]


def hash64(message, rc):
    original = [int.from_bytes(message[i:i+16], 'little') for i in range(0, 64, 16)]
    state = external(original)
    for r in range(66):
        if r < 4 or r >= 62:
            state = external([power(x ^ c, 7) for x, c in zip(state, rc[r])])
        else:
            state[0] = power(state[0] ^ rc[r][0], 7)
            total = xor(state)
            state = [total ^ x ^ mul(c, x) for c, x in zip(DIAG, state)]
    return b''.join((x ^ y).to_bytes(16, 'little') for x, y in zip(state[:2], original[:2]))


def dataset(i):
    return (2*i+1).to_bytes(32, 'little') + (2*i+2).to_bytes(32, 'little')


if __name__ == '__main__':
    rc = constants()
    messages = [bytes(64), bytes([255])*64, bytes(range(64)), dataset(0), dataset(2047)]
    data = {'modulus': 'x^128+x^7+x^2+x+1', 'mode': 'left2(P(x)+x)',
            'round_constants': [[f'{x:032x}' for x in row] for row in rc],
            'hashes': [{'input': m.hex(), 'digest': hash64(m, rc).hex()} for m in messages]}
    out = Path(__file__).resolve().parents[1] / 'tests/reference-vectors.json'
    out.write_text(json.dumps(data, indent=2)+'\n')
    print(out)
