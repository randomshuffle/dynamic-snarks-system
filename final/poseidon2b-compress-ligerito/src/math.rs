use flock_core::field::F128 as F;
use rayon::prelude::*;
pub fn fold(values: &mut Vec<F>, x: F) {
    for i in 0..values.len() / 2 {
        values[i] = values[2 * i] + (values[2 * i] + values[2 * i + 1]) * x;
    }
    values.truncate(values.len() / 2);
}
pub fn evaluate(values: &[F], point: &[F]) -> F {
    assert_eq!(values.len(), 1 << point.len());
    let mut v = values.to_vec();
    for &x in point {
        fold(&mut v, x);
    }
    v[0]
}
pub fn eq_table(point: &[F]) -> Vec<F> {
    let mut v = vec![F::ONE];
    for &x in point {
        let n = v.len();
        v.resize(2 * n, F::ZERO);
        for i in 0..n {
            let next = v[i] * x;
            v[n + i] = next;
            v[i] += next;
        }
    }
    v
}
pub fn eq(left: &[F], right: &[F]) -> F {
    assert_eq!(left.len(), right.len());
    left.iter().zip(right).fold(F::ONE, |a, (&x, &y)| {
        a * ((F::ONE + x) * (F::ONE + y) + x * y)
    })
}
pub fn poly_eval(coeffs: &[F], x: F) -> F {
    coeffs.iter().rev().fold(F::ZERO, |a, &v| a * x + v)
}
/// (a + bt)^7: all eight binomial coefficients are one in characteristic two.
pub fn seventh_line(a: F, b: F) -> [F; 8] {
    let a2 = a * a;
    let a4 = a2 * a2;
    let b2 = b * b;
    let b4 = b2 * b2;
    let p = [a2 * a4, b2 * a4, a2 * b4, b2 * b4];
    [
        a * p[0],
        b * p[0],
        a * p[1],
        b * p[1],
        a * p[2],
        b * p[2],
        a * p[3],
        b * p[3],
    ]
}
pub fn fold_columns(cols: &mut [Vec<F>], point: F) {
    if rayon::current_num_threads() == 1 || cols[0].len() < 64 {
        for c in cols {
            fold(c, point);
        }
    } else {
        cols.par_iter_mut().for_each(|c| fold(c, point));
    }
}
