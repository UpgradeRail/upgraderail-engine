use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use upgraderail_analyzer::analyze;
use upgraderail_core::{ProtocolProfile, UpgradeStatus};
use upgraderail_manifest::{build, hash_file, verify_file, Config};
use upgraderail_wasm::inspect;

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Markdown,
}

#[derive(Parser)]
#[command(
    name = "upgraderail",
    version,
    about = "Soroban contract upgrade preflight engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Version,
    Inspect {
        wasm: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    Compare {
        #[arg(long)]
        current: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    Simulate {
        #[arg(long, default_value = "upgraderail.toml")]
        config: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    Check {
        #[arg(long, default_value = "upgraderail.toml")]
        config: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
}

#[derive(Subcommand)]
enum ManifestCommand {
    Build {
        #[arg(long, default_value = "upgraderail.toml")]
        config: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Hash {
        manifest: PathBuf,
    },
    Verify {
        manifest: PathBuf,
        hash: String,
    },
}

fn render_inspection(value: &upgraderail_wasm::ArtifactInspection, format: Format) -> Result<()> {
    match format {
        Format::Text | Format::Markdown => print!("{}", upgraderail_report::inspection_text(value)),
        Format::Json => println!("{}", serde_json::to_string_pretty(value)?),
    }
    Ok(())
}

fn render_analysis(
    current: &upgraderail_wasm::ArtifactInspection,
    candidate: &upgraderail_wasm::ArtifactInspection,
    result: &upgraderail_analyzer::AnalysisResult,
    format: Format,
) -> Result<()> {
    match format {
        Format::Text => print!(
            "{}",
            upgraderail_report::analysis_text(current, candidate, result)
        ),
        Format::Json => println!("{}", serde_json::to_string_pretty(result)?),
        Format::Markdown => print!("{}", upgraderail_report::analysis_markdown(result)),
    }
    Ok(())
}

fn exit_for(status: UpgradeStatus) -> i32 {
    if status == UpgradeStatus::Blocked {
        1
    } else {
        0
    }
}

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            2
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<i32> {
    match Cli::parse().command {
        Command::Version => {
            println!(
                "upgraderail {}\nprotocol profile 28",
                env!("CARGO_PKG_VERSION")
            );
            Ok(0)
        }
        Command::Inspect { wasm, format } => {
            let value = inspect(wasm, ProtocolProfile::Protocol28).context("inspection failed")?;
            render_inspection(&value, format)?;
            Ok(0)
        }
        Command::Compare {
            current,
            candidate,
            format,
        } => {
            let current = inspect(current, ProtocolProfile::Protocol28)
                .context("current artifact inspection failed")?;
            let candidate = inspect(candidate, ProtocolProfile::Protocol28)
                .context("candidate artifact inspection failed")?;
            let result = analyze(&current, &candidate);
            render_analysis(&current, &candidate, &result, format)?;
            Ok(exit_for(result.status))
        }
        Command::Simulate { config, format } => {
            let config = Config::load(config)?;
            let version = upgraderail_simulator::stellar_cli_version().await?;
            if config.simulations.is_empty() {
                println!("Stellar CLI: {version}\nRuntime simulation: NOT CONFIGURED\nAuthorization comparison: NOT TESTED");
                return Ok(0);
            }
            let cli = upgraderail_simulator::StellarCli::default();
            let mut comparisons = Vec::new();
            for scenario in &config.simulations {
                comparisons.push(
                    upgraderail_simulator::run_scenario(
                        &cli,
                        scenario,
                        &config.resource_thresholds,
                    )
                    .await?,
                );
            }
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&comparisons)?),
                Format::Text | Format::Markdown => {
                    println!("Stellar CLI: {version}\nRuntime simulation:");
                    for comparison in &comparisons {
                        println!(
                            "  {}: current={} candidate={}",
                            comparison.current.scenario,
                            comparison.current.success,
                            comparison.candidate.success
                        );
                        for finding in &comparison.findings {
                            println!(
                                "  {:?} {}: {}",
                                finding.severity, finding.code, finding.message
                            );
                        }
                    }
                }
            }
            Ok(0)
        }
        Command::Check { config, format } => {
            let config = Config::load(config)?;
            let current = inspect(&config.analysis.current_wasm, ProtocolProfile::Protocol28)?;
            let candidate = inspect(&config.analysis.candidate_wasm, ProtocolProfile::Protocol28)?;
            let manifest = build(&config)?;
            render_analysis(&current, &candidate, &manifest.analysis, format)?;
            Ok(exit_for(manifest.analysis.status))
        }
        Command::Manifest { command } => match command {
            ManifestCommand::Build { config, out } => {
                let config = Config::load(config)?;
                let manifest = build(&config)?;
                let hash = upgraderail_manifest::write(&manifest, &out)?;
                println!("{}  {}", hash, out.display());
                Ok(exit_for(manifest.analysis.status))
            }
            ManifestCommand::Hash { manifest } => {
                println!("{}", hash_file(manifest)?);
                Ok(0)
            }
            ManifestCommand::Verify { manifest, hash } => {
                if verify_file(manifest, &hash)? {
                    println!("manifest hash verified");
                    Ok(0)
                } else {
                    eprintln!("manifest hash mismatch");
                    Ok(1)
                }
            }
        },
    }
}
