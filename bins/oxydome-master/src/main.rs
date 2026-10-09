//! Oxydome master node binary.
//!
//! Masters approve software manifests, admit server nodes, audit proposed blocks
//! (header-only, via Merkle proofs) and keep the header chain and governance sets.

use anyhow::{Context, Result};
use oxydome_core::AppConfig;
use oxydome_master::MasterNode;
use oxydome_state::ChainState;

fn usage() -> ! {
    eprintln!(
        "usage:
  oxydome-master init --out <genesis.toml> [--masters N] [--nodes M] [--supply S]
  oxydome-master --config <genesis.toml> --name <endpoint-name> [--listen <addr>]"
    );
    std::process::exit(2);
}

fn parse_key_value_args(
    args: &[String],
) -> (std::collections::BTreeMap<String, String>, Vec<String>) {
    let mut flags = std::collections::BTreeMap::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "--name" | "--listen" | "--out" | "--masters" | "--nodes" | "--supply" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                flags.insert(args[i - 1].clone(), args[i].clone());
            }
            "--init" => {
                flags.insert("--init".into(), "true".into());
            }
            s if s.starts_with("--listen=") => {
                flags.insert("--listen".into(), s["--listen=".len()..].to_string());
            }
            s if s.starts_with('-') => usage(),
            s => positional.push(s.to_string()),
        }
        i += 1;
    }
    (flags, positional)
}

fn load_config(path: &str) -> Result<AppConfig> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("cannot read config {path}"))?;
    Ok(serde_json::from_str(&raw).with_context(|| format!("cannot parse config {path}"))?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (flags, _positional) = parse_key_value_args(&args);

    // ---- init ----
    if flags.contains_key("--init") {
        let out = flags
            .get("--out")
            .map(String::as_str)
            .unwrap_or("config/genesis.json");
        let masters: usize = flags
            .get("--masters")
            .and_then(|s| s.parse().ok())
            .unwrap_or(4);
        let nodes: usize = flags
            .get("--nodes")
            .and_then(|s| s.parse().ok())
            .unwrap_or(4);
        let supply: u128 = flags
            .get("--supply")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_000_000_000_000_000);
        if let Some(parent) = std::path::Path::new(out).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let config = oxydome_node::default_config(masters, nodes, supply);
        std::fs::write(out, serde_json::to_string_pretty(&config)?)
            .with_context(|| format!("cannot write {out}"))?;
        println!("generated {out}");
        println!("then run each process, e.g.:");
        println!("  oxydome-master --config {out} --name master-0 --listen 127.0.0.1:7000");
        println!("  oxydome-node   --config {out} --name node-0   --listen 127.0.0.1:8000");
        return Ok(());
    }

    let config_path = flags.get("--config").map(String::as_str);
    let name = flags.get("--name").map(String::as_str);
    let Some(config_path) = config_path else {
        usage();
    };
    let Some(name) = name else {
        usage();
    };

    let config = load_config(config_path)?;
    let listen = flags
        .get("--listen")
        .map(String::as_str)
        .unwrap_or_default();
    let listen = if listen.is_empty() {
        config.master(name)?.addr.clone()
    } else {
        listen.to_string()
    };

    let genesis_cfg = config
        .genesis()
        .context("genesis configuration is invalid")?;
    let (_, genesis_block, gov) =
        ChainState::genesis(&genesis_cfg).context("genesis state could not be built")?;

    let key = config
        .master(name)?
        .keypair()
        .context("missing master key")?;
    let mut node = MasterNode::new(key, gov, genesis_cfg.params.clone(), &genesis_block);
    for root in config.approved_manifest_roots()? {
        node.registry.approve_manifest(root);
    }

    println!(
        "oxydome-master {} listening on {} (masters={}, approve_manifests={})",
        name,
        listen,
        node.gov.masters.len(),
        node.approved_manifests().len(),
    );

    oxydome_master::server::run(&listen, node).await?;
    Ok(())
}
