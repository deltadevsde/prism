use anyhow::Result;
use prism_presets::{FullNodePreset, LightClientPreset, ProverPreset};

use crate::{
    apply_args::{
        CliOverridableConfig,
        da::{apply_full_node_da_args, apply_light_client_da_args},
        database::apply_database_args,
        webserver::apply_webserver_args,
    },
    cli_args::{FullNodeCliArgs, LightClientCliArgs, ProverCliArgs},
    config::{CliFullNodeConfig, CliLightClientConfig, CliProverConfig},
};

impl CliOverridableConfig<LightClientPreset> for CliLightClientConfig {
    type CliArgs = LightClientCliArgs;

    fn apply_cli_args(&mut self, args: &Self::CliArgs) -> Result<()> {
        apply_light_client_da_args(&mut self.da, &args.da)?;

        if let Some(verifying_key_str) = &args.verifying_key {
            self.light_client.verifying_key_str = verifying_key_str.clone();
        }

        Ok(())
    }
}

impl CliOverridableConfig<FullNodePreset> for CliFullNodeConfig {
    type CliArgs = FullNodeCliArgs;

    fn apply_cli_args(&mut self, args: &Self::CliArgs) -> Result<()> {
        apply_database_args(&mut self.db, &args.db)?;
        apply_full_node_da_args(&mut self.da, &args.da)?;
        apply_webserver_args(&mut self.full_node.webserver, &args.web)?;

        if let Some(verifying_key_str) = &args.verifying_key {
            self.full_node.verifying_key_str = verifying_key_str.clone();
        }

        if let Some(start_height) = args.start_height {
            self.full_node.start_height = start_height;
        }

        Ok(())
    }
}

impl CliOverridableConfig<ProverPreset> for CliProverConfig {
    type CliArgs = ProverCliArgs;

    fn apply_cli_args(&mut self, args: &Self::CliArgs) -> Result<()> {
        apply_database_args(&mut self.db, &args.db)?;
        apply_full_node_da_args(&mut self.da, &args.da)?;
        apply_webserver_args(&mut self.prover.webserver, &args.web)?;

        if let Some(signing_key) = &args.signing_key {
            self.prover.signing_key_path = signing_key.clone();
        }

        if let Some(max_epochless_gap) = args.max_epochless_gap {
            self.prover.max_epochless_gap = max_epochless_gap;
        }

        if let Some(start_height) = args.start_height {
            self.prover.start_height = start_height;
        }

        if let Some(recursive_proofs) = args.recursive_proofs {
            self.prover.recursive_proofs = recursive_proofs;
        }

        Ok(())
    }
}
