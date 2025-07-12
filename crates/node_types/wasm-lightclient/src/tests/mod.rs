#[cfg(test)]
mod tests {
    use crate::{client::WasmLightClient, worker::LightClientWorker};
    use js_sys::Promise;
    use prism_common::digest::Digest;
    use prism_da::{
        EpochCommitments, MockLightDataAvailabilityLayer, MockVerifiableStateTransition,
        VerifiableStateTransition,
    };
    use prism_errors::EpochVerificationError;
    use prism_events::{EventChannel, PrismEvent};
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

    // helper functions: create message port like object, delay, and events similar to Ryans
    // approach
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

        delay_ms(50).await;

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
        F: Fn(String) + 'static,
    {
        let callback = Closure::wrap(Box::new(move |event: MessageEvent| {
            // Extract formatted_log and pass it to the handler
            if let Some(formatted_log) = extract_formatted_log(&event.data()) {
                handler(formatted_log);
            } else {
                // Fallback to string representation
                if let Some(event_str) = event.data().as_string() {
                    handler(event_str);
                }
            }
        }) as Box<dyn Fn(MessageEvent)>);

        broadcast_channel.set_onmessage(Some(callback.as_ref().unchecked_ref()));
        callback
    }

    fn extract_formatted_log(js_value: &JsValue) -> Option<String> {
        js_sys::Reflect::get(js_value, &JsValue::from_str("formatted_log"))
            .ok()
            .and_then(|v| v.as_string())
    }

    #[wasm_bindgen_test]
    async fn test_worker_command_response_flow() {
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

    #[wasm_bindgen_test]
    async fn test_da_events_forwarded_to_broadcast_channel() {
        let mock_da = MockLightDataAvailabilityLayer::new();
        let setup = setup_worker_and_client(mock_da).await;

        let broadcast_channel = setup.client.events_channel().await.unwrap();

        let received_events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = received_events.clone();

        let _callback = setup_event_listener(&broadcast_channel, move |data| {
            events_clone.lock().unwrap().push(data);
        });

        let publisher = setup.event_channel.publisher();
        publisher.send(PrismEvent::UpdateDAHeight { height: 100 });
        delay_ms(100).await;

        // Ready and height update to 100 should be received
        let events = received_events.lock().unwrap();

        console::log_1(&format!("Received events: {:?}", events).into());
        assert!(events.len() > 0);
        assert!(events.iter().any(|event| event.contains("Updated DA height to 100")));
    }

    #[wasm_bindgen_test]
    async fn test_successful_epoch_verification() {
        let mut mock_da = MockLightDataAvailabilityLayer::new();
        // Mock successful epoch verification
        mock_da.expect_get_finalized_epochs().times(1).returning(|height| {
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
        let setup = setup_worker_and_client(mock_da).await;
        delay_ms(50).await;

        let publisher = setup.event_channel.publisher();
        publisher.send(PrismEvent::UpdateDAHeight { height: 100 });

        delay_ms(50).await;

        // Check that the commitment was updated
        let commitment = setup.client.get_current_commitment().await.unwrap();
        assert_eq!(commitment, Digest::hash(b"current").to_string());
    }

    #[wasm_bindgen_test]
    async fn test_failed_epoch_verification() {
        let mut mock_da = MockLightDataAvailabilityLayer::new();
        // Mock failed epoch verification
        mock_da.expect_get_finalized_epochs().returning(|height| {
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
        delay_ms(50).await;

        let publisher = setup.event_channel.publisher();
        publisher.send(PrismEvent::UpdateDAHeight { height: 100 });
        delay_ms(50).await;

        let events = received_events.lock().unwrap();

        // Ready and height update to 100 should be received, is also be used here as test for
        // backwards sync, recursive verification etc., maybe we could write some extra tests if we
        // should separate these cases.
        assert!(events.len() > 0);
        assert!(events.iter().any(|e| e == "Updated DA height to 100"));
        assert!(events.iter().any(|e| e == "Starting backwards sync at height 100"));
        assert!(events.iter().any(|e| e == "Starting recursive verification at height 100"));
        assert!(
            events.iter().any(|e| e
                == "Failed to verify epoch 100: epoch proof verification error: Invalid proof")
        );
    }

    #[wasm_bindgen_test]
    async fn test_multiple_epochs_at_same_height() {
        let mut mock_da = MockLightDataAvailabilityLayer::new();

        mock_da.expect_get_finalized_epochs().returning(|height| {
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

        let setup = setup_worker_and_client(mock_da).await;
        setup.event_channel.publisher().send(PrismEvent::UpdateDAHeight { height: 100 });

        // Wait and verify the successful epoch was processed
        delay_ms(50).await;

        let commitment = setup.client.get_current_commitment().await.unwrap();
        assert_eq!(commitment, Digest::hash(b"curr").to_string());
    }

    #[wasm_bindgen_test]
    async fn test_concurrent_commands() {
        let mock_da = MockLightDataAvailabilityLayer::new();
        let setup = setup_worker_and_client(mock_da).await;

        // Send multiple commands concurrently
        let vefutures = vec![
            setup.client.get_current_commitment(),
            setup.client.get_current_commitment(),
            setup.client.get_current_commitment(),
        ];

        let results = futures::future::join_all(vefutures).await;

        // All should return the same error (no commitment yet)
        for result in results {
            assert!(result.is_err());
            assert!(format!("{:?}", result.unwrap_err()).contains("No commitment available"));
        }
    }

    #[wasm_bindgen_test]
    async fn test_invalid_network_initialization() {
        let channel = create_mock_port();

        // Try to create worker with non existing custom network
        let result = LightClientWorker::new(channel.port1().into(), "invalid-custom-network").await;

        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    async fn test_backwards_sync_no_epochs() {
        let mut mock_da = MockLightDataAvailabilityLayer::new();

        // No epochs at any height
        mock_da.expect_get_finalized_epochs().returning(|_| Ok(vec![]));

        let setup = setup_worker_and_client(mock_da).await;
        let broadcast_channel = setup.client.events_channel().await.unwrap();
        let received_events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = received_events.clone();

        let _callback = setup_event_listener(&broadcast_channel, move |data| {
            events_clone.lock().unwrap().push(data);
        });

        setup.event_channel.publisher().send(PrismEvent::UpdateDAHeight { height: 100 });
        delay_ms(50).await;

        let events = received_events.lock().unwrap();

        // Should complete without finding any epochs
        assert!(events.iter().any(|e| e.contains("Backwards sync complete")));
        assert!(events.iter().any(|e| e.contains("found epoch: false")));
    }
}
