use anyhow::Result;
use bellman::{gadgets::boolean::Boolean, Circuit, ConstraintSystem, SynthesisError};
use bls12_381::Scalar;
use ff::PrimeFieldBits;

#[derive(Clone)]
pub struct LessThanCircuit {
    a: Scalar,
    b: Scalar,
}

impl LessThanCircuit {
    pub fn new(a: Scalar, b: Scalar) -> LessThanCircuit {
        LessThanCircuit { a, b }
    }
}

impl Circuit<Scalar> for LessThanCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let a_bits = self.a.to_le_bits();
        let b_bits = self.b.to_le_bits();

        let mut result = Boolean::constant(false);

        for i in (0..a_bits.len()).rev() {
            let a_val = Boolean::constant(a_bits[i]);
            let b_val = Boolean::constant(b_bits[i]);
            let not_a = a_val.not();
            let not_b = b_val.not();

            let a_and_b = Boolean::and(cs.namespace(|| format!("a_and_b_{}", i)), &a_val, &b_val)?;
            let not_a_and_not_b = Boolean::and(
                cs.namespace(|| format!("not_a_and_not_b_{}", i)),
                &not_a,
                &not_b,
            )?;

            if not_a_and_not_b.get_value().unwrap() || a_and_b.get_value().unwrap() {
                continue;
            } else {
                result = Boolean::and(
                    cs.namespace(|| format!("b_and_not_a_{}", i)),
                    &b_val,
                    &not_a,
                )?;
                break;
            }
        }

        cs.enforce(
            || "a < b",
            |_| result.lc(CS::one(), Scalar::one()),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        Ok(())
    }
}
