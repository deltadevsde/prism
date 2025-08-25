use std::{sync::Arc, time::Duration};

use prism_common::digest::Digest;
use prism_da::{
    MockLightDataAvailabilityLayer, MockVerifiableStateTransition, VerifiableStateTransition,
};
use prism_errors::EpochVerificationError;
use prism_events::{EventChannel, EventPublisher, EventSubscriber, PrismEvent};
use prism_keys::SigningKey;
use tokio::spawn;
use tokio_util::sync::CancellationToken;

use crate::LightClient;

fn init_logger() {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module("tracing", log::LevelFilter::Off)
        .filter_module("sp1_stark", log::LevelFilter::Info)
        .filter_module("jmt", log::LevelFilter::Off)
        .filter_module("p3_dft", log::LevelFilter::Off)
        .filter_module("p3_fri", log::LevelFilter::Off)
        .filter_module("sp1_core_executor", log::LevelFilter::Info)
        .filter_module("sp1_recursion_program", log::LevelFilter::Info)
        .filter_module("sp1_prover", log::LevelFilter::Info)
        .filter_module("p3_merkle_tree", log::LevelFilter::Off)
        .filter_module("sp1_recursion_compiler", log::LevelFilter::Off)
        .filter_module("sp1_core_machine", log::LevelFilter::Off)
        .init();
}

macro_rules! mock_da {
    ($(($height:expr, $($spec:tt),+)),* $(,)?) => {{
        let mut mock_da = MockLightDataAvailabilityLayer::new();
        mock_da.expect_get_finalized_epochs().returning(move |height| {
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
        PrismEvent::EpochVerified { height }
        | PrismEvent::EpochVerificationFailed { height, .. } => height >= target_height,
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
    init_logger();

    let chan = EventChannel::new();
    let publisher = chan.publisher();
    let arced_chan = Arc::new(chan);
    mock_da.expect_event_channel().return_const(arced_chan.clone());

    let mock_da = Arc::new(mock_da);

    let prover_key = SigningKey::new_ed25519();
    let lc = Arc::new(LightClient::new(
        mock_da,
        prover_key.verifying_key(),
        CancellationToken::new(),
    ));

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
    wait_for_event(&mut sub, |event| {
        matches!(event, PrismEvent::HistoricalSyncStarted { height: 3 })
    })
    .await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 4 });
    wait_for_sync(&mut sub, 4).await;
    assert_current_commitment!(lc, "a");

    publisher.send(PrismEvent::UpdateDAHeight { height: 5 });
    wait_for_sync(&mut sub, 5).await;
    assert_current_commitment!(lc, "b");

    publisher.send(PrismEvent::UpdateDAHeight { height: 6 });
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
async fn test_incoming_sync_ignores_error() {
    let (lc, mut sub, publisher) =
        setup(mock_da![(8, ("a", "b")), (10, "Error"), (12, ("c", "d"))]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 8 });
    wait_for_sync(&mut sub, 8).await;
    assert_current_commitment!(lc, "b");

    publisher.send(PrismEvent::UpdateDAHeight { height: 10 });
    publisher.send(PrismEvent::UpdateDAHeight { height: 12 });
    wait_for_sync(&mut sub, 12).await;
    assert_current_commitment!(lc, "d");
}

#[tokio::test]
async fn test_sandwiched_epoch() {
    let (lc, mut sub, publisher) = setup(mock_da![(8, "Error1", ("a", "b"), "Error2")]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 8 });
    wait_for_sync(&mut sub, 8).await;
    assert_current_commitment!(lc, "b");
}

#[tokio::test]
async fn no_backwards_sync_underflow() {
    let (_, mut sub, publisher) = setup(mock_da![]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 50 });
    wait_for_event(&mut sub, |event| {
        if let PrismEvent::HistoricalSyncCompleted { height } = event {
            assert!(height.is_none());
            return true;
        }
        false
    })
    .await
}

#[tokio::test]
async fn no_concurrent_backwards_sync() {
    let (_, mut sub, publisher) = setup(mock_da![(999, ("a", "b"))]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 500 });
    publisher.send(PrismEvent::UpdateDAHeight { height: 1000 });

    wait_for_event(&mut sub, |event| {
        if let PrismEvent::HistoricalSyncStarted { height } = event {
            assert_eq!(height, 500);
            return true;
        }
        false
    })
    .await;

    wait_for_event(&mut sub, |event| {
        if let PrismEvent::HistoricalSyncCompleted { height } = event {
            assert!(height.is_none());
            return true;
        }
        false
    })
    .await;
}

#[tokio::test]
async fn test_backwards_sync_does_not_restart() {
    let (lc, mut sub, publisher) = setup(mock_da![(999, ("a", "b"))]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 500 });

    wait_for_event(&mut sub, |event| {
        if let PrismEvent::HistoricalSyncCompleted { height } = event {
            assert!(height.is_none());
            return true;
        }
        false
    })
    .await;
    publisher.send(PrismEvent::UpdateDAHeight { height: 1000 });
    // TODO: Find better way
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(lc.get_sync_state().await.latest_finalized_epoch.is_none());
}

#[tokio::test]
async fn test_will_not_process_older_epoch() {
    let (lc, mut sub, publisher) = setup(mock_da![(8, ("a", "b")), (9, ("c", "d"))]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 10 });
    wait_for_sync(&mut sub, 9).await;
    assert_current_commitment!(lc, "d");

    publisher.send(PrismEvent::UpdateDAHeight { height: 8 });
    // TODO: replace with event listener
    tokio::time::sleep(Duration::from_millis(200)).await;

    let sync_state = lc.get_sync_state().await;
    assert_eq!(sync_state.current_height, 9);
}

#[tokio::test]
async fn test_incoming_epoch_during_backwards_sync() {
    let (lc, mut sub, publisher) = setup(mock_da![(5000, ("a", "b")), (5101, ("c", "d"))]).await;

    let mut sub2 = lc.da.event_channel().subscribe();
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        // Start the event loop first, then send events after we're ready to receive
        let event_task = tokio::spawn(async move {
            let mut events_received = (false, false); // (recursive, backwards)

            while let Ok(event_info) = sub.recv().await {
                match event_info.event {
                    PrismEvent::RecursiveVerificationCompleted { height: _ } => {
                        assert_current_commitment!(lc, "d");
                        events_received.0 = true;
                    }
                    PrismEvent::HistoricalSyncCompleted { height } => {
                        assert!(height.is_none());
                        events_received.1 = true;
                    }
                    _ => {}
                }

                // Break when both conditions are met
                if events_received.0 && events_received.1 {
                    break;
                }
            }
            events_received
        });

        // Small delay to ensure the receiver is ready
        tokio::time::sleep(Duration::from_millis(10)).await;

        publisher.send(PrismEvent::UpdateDAHeight { height: 5100 });
        wait_for_event(&mut sub2, |event| {
            matches!(event, PrismEvent::HistoricalSyncStarted { height: 5100 })
        })
        .await;
        publisher.send(PrismEvent::UpdateDAHeight { height: 5101 });

        let (recursive_completed, backwards_completed) = event_task.await.unwrap();
        (recursive_completed, backwards_completed)
    })
    .await;

    match result {
        Ok((recursive_completed, backwards_completed)) => {
            assert!(
                recursive_completed,
                "RecursiveVerificationCompleted event not received"
            );
            assert!(
                backwards_completed,
                "BackwardsSyncCompleted event not received"
            );
        }
        Err(_) => panic!("Test timed out waiting for events"),
    }
}

#[tokio::test]
async fn test_incoming_epoch_after_backwards_sync() {
    let (lc, mut sub, publisher) = setup(mock_da![(5000, ("a", "b")), (5101, ("c", "d"))]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 5100 });
    wait_for_event(&mut sub, |event| {
        if let PrismEvent::HistoricalSyncCompleted { height } = event {
            return matches!(height, Some(5000));
        }
        false
    })
    .await;
    publisher.send(PrismEvent::UpdateDAHeight { height: 5101 });
    while let Ok(event_info) = sub.recv().await {
        if let PrismEvent::RecursiveVerificationCompleted { height: _ } = event_info.event {
            assert_current_commitment!(lc, "d");
            return;
        }
    }
}

#[tokio::test]
async fn test_backwards_sync_completes() {
    let (_, mut sub, publisher) = setup(mock_da![]).await;

    publisher.send(PrismEvent::UpdateDAHeight { height: 5100 });
    wait_for_event(&mut sub, |event| {
        if let PrismEvent::HistoricalSyncCompleted { height } = event {
            return height.is_none();
        }
        false
    })
    .await;
}

#[tokio::test]
async fn test_graceful_shutdown() {
    init_logger();
    let mut mock_da = mock_da![];

    let chan = EventChannel::new();
    let arced_chan = Arc::new(chan);
    let mut sub = arced_chan.clone().subscribe();
    mock_da.expect_event_channel().return_const(arced_chan.clone());

    let mock_da = Arc::new(mock_da);

    let prover_key = SigningKey::new_ed25519();
    let ct = CancellationToken::new();
    let lc = Arc::new(LightClient::new(
        mock_da,
        prover_key.verifying_key(),
        ct.clone(),
    ));

    let handle = spawn(async move { lc.run().await });

    // Wait for it to be ready syncing
    wait_for_event(&mut sub, |event| matches!(event, PrismEvent::Ready)).await;

    // Trigger cancellation
    ct.cancel();

    // Let the light node shut down
    assert!(handle.await.unwrap().is_ok())
}
