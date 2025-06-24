use std::{
    collections::HashMap,
    sync::{self, Arc},
    time::Duration,
};

use anyhow::Result;
use prism_common::digest::Digest;
use prism_da::{
    LightDataAvailabilityLayer, MockLightDataAvailabilityLayer, MockVerifiableStateTransition,
    VerifiableEpoch, VerifiableStateTransition,
    events::{EventChannel, PrismEvent},
};
use prism_errors::EpochVerificationError;
use prism_keys::SigningKey;
use tokio::spawn;

use crate::LightClient;

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
                            mock_da!(@make_epoch epoch, $spec, $height);
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
    (@make_epoch $epoch:ident, ($h1:expr, $h2:expr), $height:expr) => {
        let hash1 = $h1;
        let hash2 = $h2;
        $epoch.expect_height().returning(move || $height);
        $epoch.expect_verify().returning(move |_, _| {
            Ok((Digest::hash(hash1), Digest::hash(hash2)).into())
        });
    };

    // Error case - Err(...)
    (@make_epoch $epoch:ident, Err($error:expr), $height:expr) => {
        let err = $error;
        $epoch.expect_height().returning(move || $height);
        $epoch.expect_verify().returning(move |_, _| Err(err));
    };

    // String error shorthand
    (@make_epoch $epoch:ident, $error:literal, $height:expr) => {
        let err_msg = $error;
        $epoch.expect_height().returning(move || $height);
        $epoch.expect_verify().returning(move |_, _| {
            Err(EpochVerificationError::ProofVerificationError(err_msg.to_string()))
        });
    };
}

// TODO: This doesnt work fully yet, racy because the write to sync_state occurs before the update to comm
macro_rules! wait_for_height {
    ($lc:expr, $target_height:expr) => {{
        let mut sync_state = $lc.get_sync_state().await;
        while sync_state.current_height < $target_height {
            tokio::time::sleep(Duration::from_millis(10)).await;
            sync_state = $lc.get_sync_state().await;
        }
    }};
}

#[tokio::test]
async fn test_mock_da() {
    let mut mock_da = mock_da![
        (4, ("g", "a")),
        (5, ("a", "b")),
        (6, ("b", "c"), ("c", "d")),
        (7, ("d", "e")),
        // (8, "Expected Error")
    ];
    let chan = EventChannel::new();
    let publisher = chan.publisher();
    mock_da.expect_event_channel().return_const(Arc::new(chan));

    let mock_da = Arc::new(mock_da);

    let prover_key = SigningKey::new_ed25519();
    let lc = Arc::new(LightClient::new(mock_da, prover_key.verifying_key()));

    let runner = lc.clone();
    spawn(async move {
        runner.run().await.unwrap();
    });

    //TODO: Just wait for events
    tokio::time::sleep(Duration::from_secs(1)).await;
    publisher.send(PrismEvent::UpdateDAHeight { height: 3 });

    publisher.send(PrismEvent::UpdateDAHeight { height: 4 });
    wait_for_height!(lc, 4);
    assert_eq!(Digest::hash("a"), lc.get_latest_commitment().await.unwrap());

    publisher.send(PrismEvent::UpdateDAHeight { height: 5 });
    wait_for_height!(lc, 5);
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("{:?}", Digest::hash("a"));
    println!("{:?}", Digest::hash("b"));
    println!("{:?}", Digest::hash("c"));
    println!("{:?}", Digest::hash("d"));
    println!("{:?}", Digest::hash("e"));
    assert_eq!(Digest::hash("b"), lc.get_latest_commitment().await.unwrap());

    publisher.send(PrismEvent::UpdateDAHeight { height: 6 });
    wait_for_height!(lc, 6);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(Digest::hash("d"), lc.get_latest_commitment().await.unwrap());

    publisher.send(PrismEvent::UpdateDAHeight { height: 7 });
    wait_for_height!(lc, 7);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(Digest::hash("e"), lc.get_latest_commitment().await.unwrap());
}
