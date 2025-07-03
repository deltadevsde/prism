#[cfg(test)]
mod tests {
    use crate::{client::WasmLightClient, worker::LightClientWorker};
    use bincode::de;
    use js_sys::Promise;
    use prism_common::digest::Digest;
    use prism_da::{
        EpochCommitments, MockLightDataAvailabilityLayer, MockVerifiableStateTransition,
        VerifiableStateTransition,
        events::{EventChannel, PrismEvent},
    };
    use prism_errors::EpochVerificationError;
    use std::sync::{Arc, Mutex};
    use wasm_bindgen::{JsCast, JsValue, prelude::Closure};
    use wasm_bindgen_futures::{JsFuture, spawn_local};
    use wasm_bindgen_test::*;
    use web_sys::{BroadcastChannel, MessageChannel, MessageEvent, console, window};

    wasm_bindgen_test_configure!(run_in_browser);

    struct TestSetup {
        event_channel: Arc<EventChannel>,
        client: WasmLightClient,
    }

    // helper functions: create message port like object, delay, and events similar to Ryans approach
    fn create_mock_port() -> MessageChannel {
        MessageChannel::new().unwrap()
    }

    async fn delay_ms(ms: i32) {
        JsFuture::from(Promise::new(&mut |resolve, _| {
            window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms)
                .unwrap();
        }))
        .await
        .unwrap();
    }

    async fn setup_worker_and_client(mock_da: MockLightDataAvailabilityLayer) -> TestSetup {
        let event_channel = Arc::new(EventChannel::new());

        let mut mock_da = mock_da;
        mock_da.expect_event_channel().return_const(event_channel.clone());

        let mock_da_arc = Arc::new(mock_da);
        let channel = create_mock_port();

        let mut worker =
            LightClientWorker::new_with_da(channel.port1().into(), mock_da_arc).await.unwrap();

        let client = WasmLightClient::new(channel.port2().into()).await.unwrap();

        spawn_local(async move {
            worker.run().await.unwrap();
        });

        delay_ms(1000).await;

        TestSetup {
            client,
            event_channel,
        }
    }

    fn setup_event_listener<F>(
        broadcast_channel: &BroadcastChannel,
        handler: F,
    ) -> Closure<dyn Fn(MessageEvent)>
    where
        F: Fn(JsValue) + 'static,
    {
        let callback = Closure::wrap(Box::new(move |event: MessageEvent| {
            console::log_1(&event.data());
            handler(event.data());
        }) as Box<dyn Fn(MessageEvent)>);

        broadcast_channel.set_onmessage(Some(callback.as_ref().unchecked_ref()));
        callback
    }

    // 1. Test Worker Communication (Command/Response flow)
    #[wasm_bindgen_test]
    async fn test_worker_command_response_flow() {
        console::log_1(&"✅ Test1".into());
        let mock_da = MockLightDataAvailabilityLayer::new();
        let setup = setup_worker_and_client(mock_da).await;

        // Test GetCurrentCommitment when no commitment exists
        let commitment_result = setup.client.get_current_commitment().await;
        assert!(commitment_result.is_err());
        assert!(
            format!("{:?}", commitment_result.unwrap_err()).contains("No commitment available")
        );

        // Test GetEventsChannelName (maybe separate test later)
        let events_channel = setup.client.events_channel().await.unwrap();
        assert!(format!("{:?}", events_channel.name()).contains("lightclient-events-"));
    }

    // 2. Test Event Forwarding from DA to Broadcast Channel (more like testing the internal mechanism as well)
    #[wasm_bindgen_test]
    async fn test_da_events_forwarded_to_broadcast_channel() {
        let mut mock_da = MockLightDataAvailabilityLayer::new();
        let setup = setup_worker_and_client(mock_da).await;

        let broadcast_channel = setup.client.events_channel().await.unwrap();
        let publisher = setup.event_channel.publisher();
        publisher.send(PrismEvent::UpdateDAHeight { height: 100 });

        let received_events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = received_events.clone();

        setup_event_listener(&broadcast_channel, move |data| {
            events_clone.lock().unwrap().push(data);
        });

        console::log_1(&JsValue::from_str(&format!(
            "Received events: {:?}",
            received_events.lock().unwrap()
        )));

        // Ready and height update to 100 should be received
        let events = received_events.lock().unwrap();
        assert!(events.len() > 0);
        assert_eq!(events[0].as_string().unwrap(), "Ready");
        assert_eq!(events[1].as_string().unwrap(), "UpdateDAHeight: 100");
    }

    // 3. Test Successful Epoch Verification
    #[wasm_bindgen_test]
    async fn test_successful_epoch_verification() {
        console::log_1(&"✅ Test3".into());

        let mut mock_da = MockLightDataAvailabilityLayer::new();
        // Mock successful epoch verification
        mock_da.expect_get_finalized_epoch().times(1).returning(|height| {
            if height == 100 {
                let mut mock_epoch = MockVerifiableStateTransition::new();
                mock_epoch.expect_height().return_const(100_u64);
                mock_epoch.expect_da_height().return_const(100_u64);
                mock_epoch.expect_verify().returning(|_, _| {
                    Ok(EpochCommitments::new(
                        Digest::hash(b"previous"),
                        Digest::hash(b"current"),
                    ))
                });
                Ok(vec![Box::new(mock_epoch)])
            } else {
                Ok(vec![])
            }
        });
        let mut setup = setup_worker_and_client(mock_da).await;
        delay_ms(500).await;

        let publisher = setup.event_channel.publisher();
        publisher.send(PrismEvent::UpdateDAHeight { height: 100 });

        delay_ms(500).await;

        // Check that the commitment was updated
        let commitment = setup.client.get_current_commitment().await.unwrap();
        assert_eq!(commitment, Digest::hash(b"current").to_string());
    }

    // 4. Test Failed Epoch Verification
    #[wasm_bindgen_test]
    async fn test_failed_epoch_verification() {
        console::log_1(&"✅ Test4".into());
        let mut mock_da = MockLightDataAvailabilityLayer::new();
        // Mock failed epoch verification
        mock_da.expect_get_finalized_epoch().returning(|height| {
            if height == 100 {
                let mut mock_epoch = MockVerifiableStateTransition::new();
                mock_epoch.expect_height().return_const(100 as u64);
                mock_epoch.expect_verify().returning(|_, _| {
                    Err(EpochVerificationError::ProofVerificationError(
                        "Invalid proof".to_string(),
                    ))
                });
                Ok(vec![Box::new(mock_epoch)])
            } else {
                Ok(vec![])
            }
        });

        let setup = setup_worker_and_client(mock_da).await;

        let broadcast_channel = setup.client.events_channel().await.unwrap();
        let received_events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = received_events.clone();

        let _callback = setup_event_listener(&broadcast_channel, move |data| {
            events_clone.lock().unwrap().push(data);
        });
        delay_ms(500).await;

        let publisher = setup.event_channel.publisher();
        publisher.send(PrismEvent::UpdateDAHeight { height: 100 });
        delay_ms(500).await;

        let events = received_events.lock().unwrap();
        console::log_1(&JsValue::from_str(&format!(
            "Received events: {:?}",
            events
        )));

        // Ready and height update to 100 should be received
        assert!(events.len() > 0);
        assert!(events[0].as_string().unwrap().contains("Updated DA height to 100"));
        assert!(events[1].as_string().unwrap().contains("Starting backwards sync at height 100"));
        assert!(
            events[2]
                .as_string()
                .unwrap()
                .contains("Starting recursive verification at height 100")
        );
        assert!(events[3].as_string().unwrap().contains("Failed to verify epoch 100"));
    }

    // 5. Test Multiple Epochs at Same Height
    /* #[wasm_bindgen_test]
    async fn test_multiple_epochs_at_same_height() {
        console::log_1(&"✅ Test5".into());
        let (mut mock_da, event_channel) = create_mock_da_with_events();

        mock_da.expect_get_finalized_epoch().returning(|height| {
            if height == 100 {
                let mut epochs = vec![];

                // First epoch - will fail
                let mut mock_epoch1 = MockVerifiableStateTransition::new();
                mock_epoch1.expect_height().return_const(100 as u64);
                mock_epoch1.expect_verify().returning(|_, _| {
                    Err(EpochVerificationError::ProofVerificationError(
                        "Invalid".to_string(),
                    ))
                });
                epochs.push(Box::new(mock_epoch1) as Box<dyn VerifiableStateTransition>);

                // Second epoch - will succeed
                let mut mock_epoch2 = MockVerifiableStateTransition::new();
                mock_epoch2.expect_height().return_const(100 as u64);
                mock_epoch2.expect_verify().returning(|_, _| {
                    Ok(EpochCommitments::new(
                        Digest::hash(b"prev"),
                        Digest::hash(b"curr"),
                    ))
                });
                epochs.push(Box::new(mock_epoch2) as Box<dyn VerifiableStateTransition>);

                Ok(epochs)
            } else {
                Ok(vec![])
            }
        });

        let channel = create_mock_port();

        let mut worker = LightClientWorker::new_with_da(channel.port1().into(), Arc::new(mock_da))
            .await
            .unwrap();

        let client = WasmLightClient::new(channel.port2().into()).await.unwrap();

        spawn_local(async move {
            worker.run().await.unwrap();
        });

        // Trigger processing
        event_channel.publisher().send(PrismEvent::UpdateDAHeight { height: 100 });

        // Wait and verify the successful epoch was processed
        wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 200)
                .unwrap();
        }))
        .await
        .unwrap();

        let commitment = client.get_current_commitment().await.unwrap();
        assert_eq!(commitment, Digest::hash(b"curr").to_string());

        wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 1000)
                .unwrap();
        }))
        .await
        .unwrap();
    }

    // 6. Test Backward Sync Behavior
    #[wasm_bindgen_test]
    async fn test_backward_sync_initiation() {
        console::log_1(&"✅ Test6".into());
        let (mut mock_da, event_channel) = create_mock_da_with_events();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(10);

        // Subscribe to backward sync events
        let mut subscriber = event_channel.subscribe();
        spawn_local(async move {
            while let Ok(event_info) = subscriber.recv().await {
                match event_info.event {
                    PrismEvent::BackwardsSyncStarted { height } => {
                        event_tx.send(("started", height)).await.unwrap();
                    }
                    PrismEvent::BackwardsSyncCompleted { height } => {
                        event_tx.send(("completed", height.unwrap_or(0))).await.unwrap();
                    }
                    _ => {}
                }
            }
        });

        // Mock will find epoch at height 95
        mock_da.expect_get_finalized_epoch().returning(|height| {
            if height == 95 {
                let mut mock_epoch = MockVerifiableStateTransition::new();
                mock_epoch.expect_height().return_const(95 as u64);
                mock_epoch.expect_verify().returning(|_, _| {
                    Ok(EpochCommitments::new(
                        Digest::hash(b"old_prev"),
                        Digest::hash(b"old_curr"),
                    ))
                });
                Ok(vec![Box::new(mock_epoch)])
            } else {
                Ok(vec![])
            }
        });

        let _channel = create_mock_port();

        // Start at height 100 to trigger backward sync
        event_channel.publisher().send(PrismEvent::UpdateDAHeight { height: 100 });

        // Verify backward sync started
        let (event_type, height) = event_rx.recv().await.unwrap();
        assert_eq!(event_type, "started");
        assert_eq!(height, 100);

        // Verify backward sync completed at height 95
        let (event_type, height) = event_rx.recv().await.unwrap();
        assert_eq!(event_type, "completed");
        assert_eq!(height, 95);

        wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 1000)
                .unwrap();
        }))
        .await
        .unwrap();
    }

    // 7. Test Worker Shutdown and Cleanup
    #[wasm_bindgen_test]
    async fn test_worker_shutdown() {
        console::log_1(&"✅ Test7".into());
        let (mut mock_da, _) = create_mock_da_with_events();

        mock_da.expect_get_finalized_epoch().returning(|_| Ok(vec![]));

        let channel = create_mock_port();

        let mut worker = LightClientWorker::new_with_da(channel.port1().into(), Arc::new(mock_da))
            .await
            .unwrap();

        // Close the port to simulate shutdown
        channel.port2().close();

        // Worker should handle this gracefully
        let result = worker.run().await;
        // Should complete without panic
        assert!(result.is_ok() || format!("{:?}", result.unwrap_err()).contains("Channel closed"));

        wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 1000)
                .unwrap();
        }))
        .await
        .unwrap();
    }

    // 8. Test Concurrent Command Processing
    #[wasm_bindgen_test]
    async fn test_concurrent_commands() {
        console::log_1(&"✅ Test8".into());
        let (mut mock_da, _) = create_mock_da_with_events();

        mock_da.expect_get_finalized_epoch().returning(|_| Ok(vec![]));

        let channel = create_mock_port();

        let mut worker = LightClientWorker::new_with_da(channel.port1().into(), Arc::new(mock_da))
            .await
            .unwrap();

        let client = WasmLightClient::new(channel.port2().into()).await.unwrap();

        spawn_local(async move {
            worker.run().await.unwrap();
        });

        // Send multiple commands concurrently
        let (r1, r2, r3) = futures::future::join3(
            client.get_current_commitment(),
            client.get_current_commitment(),
            client.events_channel(),
        )
        .await;

        // All should complete (though get_current_commitment will error due to no commitment)
        assert!(r1.is_err());
        assert!(r2.is_err());
        assert!(r3.is_ok());
    } */
}
