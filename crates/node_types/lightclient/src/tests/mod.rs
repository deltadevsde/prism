use std::collections::HashMap;

use anyhow::Result;
use prism_common::digest::Digest;
use prism_da::{
    EpochVerificationError, MockLightDataAvailabilityLayer, MockVerifiableStateTransition,
    VerifiableEpoch, VerifiableStateTransition,
};

macro_rules! mock_da {
    ($(($height:expr, $($spec:tt),+)),* $(,)?) => {{
        let mut mock_da = MockLightDataAvailabilityLayer::new();
        mock_da.expect_get_finalized_epoch().returning(move |height| {
            match height {
                $(
                    $height => {
                        let mut transitions = vec![];
                        $(
                            let mut epoch = MockVerifiableStateTransition::new();
                            mock_da!(@make_epoch epoch, $spec);
                            transitions.push(Box::new(epoch) as Box<dyn VerifiableStateTransition>);
                        )+
                        Ok(transitions)
                    }
                )*
                _ => Ok(vec![]),
            }
        });
        mock_da
    }};

    // Success case - tuple
    (@make_epoch $epoch:ident, ($h1:expr, $h2:expr)) => {
        let hash1 = $h1;
        let hash2 = $h2;
        $epoch.expect_verify().returning(move |_, _| {
            Ok((Digest::hash(hash1), Digest::hash(hash2)))
        });
    };

    // Error case - Err(...)
    (@make_epoch $epoch:ident, Err($error:expr)) => {
        let err = $error;
        $epoch.expect_verify().returning(move |_, _| Err(err));
    };

    // String error shorthand
    (@make_epoch $epoch:ident, $error:literal) => {
        let err_msg = $error;
        $epoch.expect_verify().returning(move |_, _| {
            Err(EpochVerificationError::ProofVerificationError(err_msg.to_string()))
        });
    };
}

fn setup() {
    let mut mock_da = MockLightDataAvailabilityLayer::new();
    mock_da![
        (5, ("abc", "def")),
        (6, ("ghi", "jkl"), ("xyz", "yuu")),
        (7, ("mno", "pqr")),
        (8, "Expected Error")
    ];
}
