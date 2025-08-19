use clap::Args;
use serde::Deserialize;

#[derive(Args, Deserialize, Clone, Debug, Default)]
#[group(required = false, multiple = true)]
pub struct CliWebserverArgs {
    #[arg(long)]
    pub webserver_active: Option<bool>,

    /// IP address for the webserver to listen on
    #[arg(long, required_if_eq("webserver_active", "true"))]
    pub host: Option<String>,

    /// Port number for the webserver to listen on
    #[arg(short, long, required_if_eq("webserver_active", "true"))]
    pub port: Option<u16>,
}
