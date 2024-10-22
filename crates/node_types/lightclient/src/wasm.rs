use anyhow::{anyhow, Context, Result};
use celestia_types::{nmt::Namespace, Blob, TxConfig};
use prism_common::operation::Operation;
use prism_da::FinalizedEpoch;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct WasmOptionalFinalizedEpoch(Option<String>);

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct WasmOperations(Vec<String>);

impl WasmOptionalFinalizedEpoch {
    pub fn from_option(epoch: Option<FinalizedEpoch>) -> Result<Self, JsValue> {
        let json = epoch
            .map(|e| serde_json::to_string(&e))
            .transpose()
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        Ok(WasmOptionalFinalizedEpoch(json))
    }

    pub fn to_option(&self) -> Result<Option<FinalizedEpoch>, JsValue> {
        self.0
            .as_ref()
            .map(|json| serde_json::from_str(json))
            .transpose()
            .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))
    }
}

impl WasmOperations {
    pub fn from_vec(ops: Vec<Operation>) -> Result<Self, JsValue> {
        let json_ops: Result<Vec<String>, _> = ops
            .into_iter()
            .map(|op| {
                serde_json::to_string(&op)
                    .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
            })
            .collect();
        Ok(WasmOperations(json_ops?))
    }

    pub fn to_vec(&self) -> Result<Vec<Operation>, JsValue> {
        self.0
            .iter()
            .map(|json| {
                serde_json::from_str(json)
                    .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))
            })
            .collect()
    }
}

#[cfg(feature = "wasm")]
#[derive(Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WasmDataAvailabilityLayer {
    base_url: String,
    start_height: u64,
    snark_namespace_id: String,
    operation_namespace_id: Option<String>,
}

/* pub struct WasmCelestiaConnection {
    config: WasmCelestiaConfig,
}

impl WasmCelestiaConnection {
    pub fn new(config: WasmCelestiaConfig) -> Self {
        Self { config }
    }

    async fn fetch<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        method: &str,
        body: Option<&str>,
    ) -> Result<T> {
        let mut opts = RequestInit::new();
        opts.method(method);
        opts.mode(RequestMode::Cors);

        if let Some(body_str) = body {
            opts.body(Some(&JsValue::from_str(body_str)));
        }

        let url = format!("{}{}", self.config.base_url, endpoint);
        let request = Request::new_with_str_and_init(&url, &opts)?;
        request.headers().set("Content-Type", "application/json")?;

        let window = web_sys::window().ok_or_else(|| anyhow!("No window found"))?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| anyhow!("Failed to cast response"))?;

        if !resp.ok() {
            return Err(anyhow!("HTTP error: {}", resp.status()));
        }

        let json = JsFuture::from(resp.json()?).await?;
        let result: T = json
            .into_serde()
            .map_err(|e| anyhow!("Failed to parse JSON: {}", e))?;
        Ok(result)
    }
} */

pub fn create_namespace(namespace_hex: &str) -> Result<Namespace> {
    let decoded_hex = hex::decode(namespace_hex).context(format!(
        "Failed to decode namespace hex '{}'",
        namespace_hex
    ))?;

    Namespace::new_v0(&decoded_hex).context(format!(
        "Failed to create namespace from '{}'",
        namespace_hex
    ))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmDataAvailabilityLayer {
    #[wasm_bindgen(constructor)]
    pub fn new(
        base_url: String,
        start_height: u64,
        snark_namespace_id: String,
        operation_namespace_id: Option<String>,
    ) -> Self {
        WasmDataAvailabilityLayer {
            base_url,
            start_height,
            snark_namespace_id,
            operation_namespace_id,
        }
    }

    async fn fetch<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        method: &str,
        body: Option<&str>,
    ) -> Result<T, JsValue> {
        let opts = RequestInit::new();
        opts.set_method(method);
        opts.set_mode(RequestMode::Cors);

        if let Some(body_str) = body {
            opts.set_body(&JsValue::from_str(body_str));
        }

        let url = format!("{}{}", self.base_url, endpoint);
        let request = Request::new_with_str_and_init(&url, &opts)?;
        request.headers().set("Content-Type", "application/json")?;

        let window = web_sys::window().ok_or_else(|| JsValue::from_str("No window found"))?;
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into()?;

        if !resp.ok() {
            return Err(JsValue::from_str(&format!("HTTP error: {}", resp.status())));
        }

        let json = JsFuture::from(resp.json()?).await?;
        let result: T = from_value(json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;
        Ok(result)
    }

    #[wasm_bindgen]
    pub async fn get_latest_height(&self) -> Result<u64, JsValue> {
        #[derive(Deserialize)]
        struct HeightResponse {
            height: u64,
        }

        let response: HeightResponse = self.fetch("/header/network_head", "GET", None).await?;
        Ok(response.height)
    }

    #[wasm_bindgen(getter)]
    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn start_height(&self) -> u64 {
        self.start_height
    }

    #[wasm_bindgen(getter)]
    pub fn snark_namespace_id(&self) -> String {
        self.snark_namespace_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn operation_namespace_id(&self) -> Option<String> {
        self.operation_namespace_id.clone()
    }

    #[wasm_bindgen]
    pub async fn get_finalized_epoch(
        &self,
        height: u64,
    ) -> Result<WasmOptionalFinalizedEpoch, JsValue> {
        let endpoint = format!("/blob/get_all/{}", height);
        let body = serde_json::to_string(&self.snark_namespace_id)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        let blobs: Option<Vec<Blob>> = self.fetch(&endpoint, "POST", Some(&body)).await?;

        let epoch = match blobs {
            Some(blobs) if !blobs.is_empty() => {
                let epoch = FinalizedEpoch::try_from(&blobs[0])
                    .map_err(|e| JsValue::from_str(&format!("Conversion error: {}", e)))?;
                Some(epoch)
            }
            _ => None,
        };

        WasmOptionalFinalizedEpoch::from_option(epoch)
    }

    #[wasm_bindgen]
    pub async fn get_operations(&self, height: u64) -> Result<WasmOperations, JsValue> {
        let endpoint = format!("/blob/get_all/{}", height);
        let body = serde_json::to_string(&self.operation_namespace_id)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        let blobs: Option<Vec<Blob>> = self.fetch(&endpoint, "POST", Some(&body)).await?;

        let operations = match blobs {
            Some(blobs) => blobs
                .into_iter()
                .filter_map(|blob| Operation::try_from(&blob).ok())
                .collect(),
            None => vec![],
        };

        WasmOperations::from_vec(operations)
    }

    async fn start(&self) -> Result<()> {
        // For Wasm, we don't need to start anything explicitly
        Ok(())
    }

    /* fn subscribe_to_heights(&self) -> broadcast::Receiver<u64> {
        // WebAssembly doesn't support multi-threading in the same way as native Rust
        // We'll need to implement this differently, perhaps using a JavaScript callback
        unimplemented!("Height subscription not implemented for Wasm")
    } */
}
