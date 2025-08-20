use anyhow::Result;
use prism_prover::WebServerConfig;

use crate::cli_args::CliWebserverArgs;

pub fn apply_webserver_args(config: &mut WebServerConfig, args: &CliWebserverArgs) -> Result<()> {
    if let Some(active) = args.webserver_active {
        config.enabled = active;
    }

    if let Some(host) = &args.host {
        config.host = host.clone();
    }

    if let Some(port) = args.port {
        config.port = port;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use prism_prover::WebServerConfig;

    use crate::cli_args::CliWebserverArgs;

    #[test]
    fn test_webserver_args_application() -> Result<()> {
        use crate::apply_args::webserver::apply_webserver_args;

        let mut config = WebServerConfig {
            enabled: false,
            host: "0.0.0.0".to_string(),
            port: 8080,
        };

        let web_args = CliWebserverArgs {
            webserver_active: Some(true),
            host: Some("127.0.0.1".to_string()),
            port: Some(3000),
        };

        apply_webserver_args(&mut config, &web_args)?;

        assert!(config.enabled);
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 3000);

        Ok(())
    }
}
