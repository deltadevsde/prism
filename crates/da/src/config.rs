use serde::Deserialize;

#[derive(Debug, Default, Clone, Eq, PartialEq, Deserialize)]
#[cfg_attr(feature = "serde", derive(SerializeDisplay, DeserializeFromStr))]
pub enum DALayerOption {
    #[default]
    Celestia,
    InMemory,
    None,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CelestiaConfig {
    pub connection_string: String,
    pub namespace_id: String,
}

impl Default for CelestiaConfig {
    fn default() -> Self {
        CelestiaConfig {
            connection_string: "ws://localhost:26658".to_string(),
            namespace_id: "00000000000000de1008".to_string(),
        }
    }
}
