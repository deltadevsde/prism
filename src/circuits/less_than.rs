use anyhow::Result;
use bellpepper_core::{boolean::Boolean, Circuit, ConstraintSystem, SynthesisError};
use blstrs::Scalar;
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

        // Iterate over the bits from most significant to least significant
        for i in (0..a_bits.len()).rev() {
            let a_val = Boolean::constant(a_bits[i]);
            let b_val = Boolean::constant(b_bits[i]);
            let not_a = a_val.not();
            let not_b = b_val.not();

            // Check if bits are equal (both 1 or both 0)
            let a_and_b = Boolean::and(cs.namespace(|| format!("a_and_b_{}", i)), &a_val, &b_val)?;
            let not_a_and_not_b = Boolean::and(
                cs.namespace(|| format!("not_a_and_not_b_{}", i)),
                &not_a,
                &not_b,
            )?;

            // If the bits are equal, continue to the next bit
            if not_a_and_not_b.get_value().unwrap() || a_and_b.get_value().unwrap() {
                continue;
            } else {
                // If bits differ: b > a if b_bit = 1 && a_bit = 0
                result = Boolean::and(
                    cs.namespace(|| format!("b_and_not_a_{}", i)),
                    &b_val,
                    &not_a,
                )?;
                break;
            }
        }

        // Enforce the constraint that the result is correct
        // If result is true, then a < b, otherwise a >= b
        // result * (1) = 1
        cs.enforce(
            || "a < b",
            |_| result.lc(CS::one(), Scalar::from(1)),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        Ok(())
    }
}
