use clap::Args;
use serde::Deserialize;

#[derive(Args, Deserialize, Clone, Debug, Default)]
#[group(required = false, multiple = true)]
pub struct CliWebserverArgs {
    #[arg(long)]
    pub webserver_active: Option<bool>,

    /// IP address for the webserver to listen on
    #[arg(long, requires = "webserver_active", default_value = "127.0.0.1")]
    pub host: Option<String>,

    /// Port number for the webserver to listen on
    #[arg(short, long, requires = "webserver_active", default_value = "41997")]
    pub port: Option<u16>,
}
