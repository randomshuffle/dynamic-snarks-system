//! Poseidon2b n=128,t=4 compression: left_2(P(x) + x), in Flock's GHASH basis.
//! Paper 2025/1893 §3.1.2, Table 1, and the authors' Sage parameter recipe.
use flock_core::field::F128 as F;
use sha3::{
    TurboShake256, TurboShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::sync::OnceLock;

pub const WIDTH: usize = 4;
pub const HASH_ROUNDS: usize = 66;
pub type State = [F; WIDTH];
pub const fn field(x: u128) -> F {
    F::new(x as u64, (x >> 64) as u64)
}
pub fn integer(x: F) -> u128 {
    x.lo as u128 | ((x.hi as u128) << 64)
}
const EXTERNAL: [[u128; 4]; 4] = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];
const DIAG: [u128; 4] = [1 << 5, 1 << 13, 1 << 9, 1 << 11];

pub fn constants() -> &'static [[F; WIDTH]; HASH_ROUNDS] {
    static RC: OnceLock<[[F; WIDTH]; HASH_ROUNDS]> = OnceLock::new();
    RC.get_or_init(|| {
        let mut shake = TurboShake256::from_core(TurboShake256Core::new(0x1f));
        shake.update(b"Poseidon2b");
        for chunk in [0u64, 0, 1] {
            shake.update(&chunk.to_le_bytes());
        }
        let mut reader = shake.finalize_xof();
        std::array::from_fn(|_| {
            std::array::from_fn(|_| {
                loop {
                    let mut buf = [0u8; 17];
                    reader.read(&mut buf);
                    if buf[16] == 0 {
                        break field(u128::from_le_bytes(buf[..16].try_into().unwrap()));
                    }
                }
            })
        })
    })
}
#[inline]
pub fn pow7(x: F) -> F {
    let x2 = x * x;
    let x4 = x2 * x2;
    (x * x2) * x4
}
#[inline]
pub fn full(round: usize) -> bool {
    !(4..62).contains(&round)
}
#[inline]
fn coefficient(c: u128, x: F) -> F {
    if c == 1 { x } else { field(c) * x }
}
pub fn external(state: &mut State) {
    let previous = *state;
    for i in 0..WIDTH {
        state[i] = (0..WIDTH).fold(F::ZERO, |s, j| s + coefficient(EXTERNAL[i][j], previous[j]));
    }
}
pub fn internal(state: &mut State) {
    let sum = state.iter().fold(F::ZERO, |s, &x| s + x);
    for i in 0..WIDTH {
        state[i] = sum + state[i] + coefficient(DIAG[i], state[i]);
    }
}
pub fn before_sbox(round: usize, state: &mut State) {
    if round == 0 {
        external(state);
    }
    let rc = &constants()[round];
    if full(round) {
        for i in 0..WIDTH {
            state[i] += rc[i];
        }
    } else {
        state[0] += rc[0];
    }
}
pub fn round(round: usize, mut state: State) -> State {
    before_sbox(round, &mut state);
    if full(round) {
        for x in &mut state {
            *x = pow7(*x);
        }
        external(&mut state);
    } else {
        state[0] = pow7(state[0]);
        internal(&mut state);
    }
    state
}
pub fn sbox_weights(round: usize, weights: State) -> State {
    std::array::from_fn(|j| {
        (0..WIDTH).fold(F::ZERO, |s, i| {
            let c = if full(round) {
                EXTERNAL[i][j]
            } else if i == j {
                DIAG[i]
            } else {
                1
            };
            s + coefficient(c, weights[i])
        })
    })
}
/// All 512 input bits are data; no domain prefix, capacity words, or padding.
pub fn input(message: &[u8; 64]) -> State {
    std::array::from_fn(|i| {
        field(u128::from_le_bytes(
            message[16 * i..16 * i + 16].try_into().unwrap(),
        ))
    })
}
pub fn hash64(message: &[u8; 64]) -> [F; 2] {
    let x = input(message);
    let mut s = x;
    for r in 0..HASH_ROUNDS {
        s = round(r, s);
    }
    [s[0] + x[0], s[1] + x[1]]
}
pub fn dataset(i: usize) -> [u8; 64] {
    let mut m = [0; 64];
    m[..8].copy_from_slice(&((2 * i + 1) as u64).to_le_bytes());
    m[32..40].copy_from_slice(&((2 * i + 2) as u64).to_le_bytes());
    m
}
