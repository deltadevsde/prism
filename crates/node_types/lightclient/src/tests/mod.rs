use std::sync::Arc;

use prism_common::digest::Digest;
use prism_da::{
    MockLightDataAvailabilityLayer, MockVerifiableStateTransition, VerifiableStateTransition,
    events::{EventChannel, EventPublisher, EventSubscriber, PrismEvent},
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

async fn wait_for_sync(sub: &mut EventSubscriber, target_height: u64) {
    wait_for_event(sub, |event| match event {
        PrismEvent::EpochVerified { height } => height >= target_height,
        PrismEvent::EpochVerificationFailed { height, .. } => height >= target_height,
        _ => false,
    })
    .await;
}

macro_rules! assert_current_commitment {
    ($lc:expr, $expected:expr) => {
        let actual = $lc.get_latest_commitment().await.unwrap();
        assert_eq!(Digest::hash($expected), actual);
    };
}

async fn wait_for_event<F>(sub: &mut EventSubscriber, mut handler: F)
where
    F: FnMut(PrismEvent) -> bool, // return true to break the loop
{
    while let Ok(event_info) = sub.recv().await {
        if handler(event_info.event) {
            break;
        }
    }
}

async fn setup(
    mut mock_da: MockLightDataAvailabilityLayer,
) -> (Arc<LightClient>, EventSubscriber, EventPublisher) {
    let chan = EventChannel::new();
    let publisher = chan.publisher();
    let arced_chan = Arc::new(chan);
    mock_da.expect_event_channel().return_const(arced_chan.clone());

    let mock_da = Arc::new(mock_da);

    let prover_key = SigningKey::new_ed25519();
    let lc = Arc::new(LightClient::new(mock_da, prover_key.verifying_key()));

    let runner = lc.clone();
    spawn(async move {
        runner.run().await.unwrap();
    });
    let mut sub = arced_chan.clone().subscribe();
    wait_for_event(&mut sub, |event| matches!(event, PrismEvent::Ready)).await;
    (lc, sub, publisher)
}

#[tokio::test]
async fn test_realtime_sync() {
    let (lc, mut sub, publisher) = setup(mock_da![
        (4, ("g", "a")),
        (5, ("a", "b")),
        (7, ("b", "c"), ("c", "d")),
        (8, ("d", "e")),
    ])
    .await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 3 });

    publisher.send(PrismEvent::UpdateDAHeight { height: 4 });
    wait_for_sync(&mut sub, 4).await;
    assert_current_commitment!(lc, "a");

    publisher.send(PrismEvent::UpdateDAHeight { height: 5 });
    wait_for_sync(&mut sub, 5).await;
    assert_current_commitment!(lc, "b");

    publisher.send(PrismEvent::UpdateDAHeight { height: 6 });
    wait_for_sync(&mut sub, 6).await;
    assert_current_commitment!(lc, "b");

    publisher.send(PrismEvent::UpdateDAHeight { height: 7 });
    wait_for_sync(&mut sub, 7).await;
    assert_current_commitment!(lc, "d");

    publisher.send(PrismEvent::UpdateDAHeight { height: 8 });
    wait_for_sync(&mut sub, 8).await;
    assert_current_commitment!(lc, "e");
}

#[tokio::test]
async fn test_backwards_sync() {
    let (lc, mut sub, publisher) = setup(mock_da![(8, ("a", "b"))]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 20 });
    while let Ok(event_info) = sub.recv().await {
        if let PrismEvent::RecursiveVerificationCompleted { height } = event_info.event {
            assert_eq!(height, 8);
            assert_current_commitment!(lc, "b");
            return;
        }
    }
}

#[tokio::test]
async fn test_backwards_sync_ignores_error() {
    let (lc, mut sub, publisher) = setup(mock_da![(8, ("a", "b")), (10, "Error")]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 20 });
    while let Ok(event_info) = sub.recv().await {
        if let PrismEvent::RecursiveVerificationCompleted { height } = event_info.event {
            assert_eq!(height, 8);
            assert_current_commitment!(lc, "b");
            return;
        }
    }
}

#[tokio::test]
async fn test_incoming_epoch_during_backwards_sync() {
    let (lc, mut sub, publisher) = setup(mock_da![(5000, ("a", "b")), (5101, ("c", "d"))]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 5100 });
    publisher.send(PrismEvent::UpdateDAHeight { height: 5101 });
    while let Ok(event_info) = sub.recv().await {
        if let PrismEvent::RecursiveVerificationCompleted { height: _ } = event_info.event {
            assert_current_commitment!(lc, "d");
            return;
        }
    }

    let sync_state = lc.get_sync_state().await;
    assert!(sync_state.initial_sync_completed);
    assert!(!sync_state.initial_sync_in_progress);
}
