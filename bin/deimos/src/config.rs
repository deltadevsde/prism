#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webserver: Option<WebServerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub celestia_config: Option<CelestiaConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: String,
    pub da_layer: DALayerOption,
    pub redis_config: Option<RedisConfig>,
    pub epoch_time: u64,
    pub public_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            webserver: Some(WebServerConfig::default()),
            log_level: "DEBUG".to_string(),
            da_layer: DALayerOption::default(),
            celestia_config: Some(CelestiaConfig::default()),
            redis_config: Some(RedisConfig::default()),
            epoch_time: 60,
            public_key: None,
        }
    }
}

pub fn load_config(args: CommandLineArgs) -> Result<Config, config::ConfigError> {
    // let settings = ConfigBuilder::<DefaultState>::default()
    //     .add_source(File::from_str(
    //         include_str!("config.toml"),
    //         FileFormat::Toml,
    //     ))
    //     .build()?;

    // info!("{}", settings.get_string("log_level").unwrap_or_default());

    let default_config = Config::default();

    Ok(Config {
        log_level: args.log_level.unwrap_or(default_config.log_level),
        webserver: Some(WebServerConfig {
            host: args
                .host
                .unwrap_or(default_config.webserver.as_ref().unwrap().host.clone()),
            port: args
                .port
                .unwrap_or(default_config.webserver.as_ref().unwrap().port),
        }),
        da_layer: DALayerOption::default(),
        redis_config: Some(RedisConfig {
            connection_string: args.redis_client.unwrap_or(
                default_config
                    .redis_config
                    .as_ref()
                    .unwrap()
                    .connection_string
                    .clone(),
            ),
        }),
        celestia_config: Some(CelestiaConfig {
            connection_string: args.celestia_client.unwrap_or(
                default_config
                    .celestia_config
                    .as_ref()
                    .unwrap()
                    .connection_string
                    .clone(),
            ),
            namespace_id: args.celestia_namespace_id.unwrap_or(
                default_config
                    .celestia_config
                    .as_ref()
                    .unwrap()
                    .namespace_id
                    .clone(),
            ),
        }),
        epoch_time: args
            .epoch_time
            .map(|e| e as u64)
            .unwrap_or(default_config.epoch_time),
        public_key: args.public_key.or(default_config.public_key),
    })
}
