//! Oxydome server node binary.
//!
//! Holds the full chain, joins the network by obtaining a master-signed admission
//! certificate, serves liveness/sync, and can run a self-contained `demo` network
//! (masters + nodes) to observe the full protocol end to end in one process.

mod demo;

use anyhow::{Context, Result};
use oxydome_core::AppConfig;
use oxydome_node::{reference_manifest, Node};

fn usage() -> ! {
    eprintln!(
        "usage:
  oxydome-node init --out <genesis.toml> [--masters N] [--nodes M] [--supply S]
  oxydome-node demo [--blocks N] [--supply S] [--db <path>]
  oxydome-node --config <genesis.toml> --name <endpoint-name> [--listen <addr>] [--masters <addr,...>] [--db <path>]"
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
            "--config" | "--name" | "--listen" | "--out" | "--masters" | "--nodes" | "--supply"
            | "--blocks" | "--peers" | "--db" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                flags.insert(args[i - 1].clone(), args[i].clone());
            }
            "init" | "demo" => positional.push(args[i].clone()),
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
    let (flags, positional) = parse_key_value_args(&args);

    if positional.iter().any(|p| p == "demo") {
        let blocks: u64 = flags
            .get("--blocks")
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);
        let supply: u128 = flags
            .get("--supply")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_000_000_000_000);
        let db = flags.get("--db").cloned();
        return demo::run(blocks, supply, db);
    }

    if positional.iter().any(|p| p == "init") || flags.contains_key("--init") {
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
            .unwrap_or(1_000_000_000);
        if let Some(parent) = std::path::Path::new(out).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let config = oxydome_node::default_config(masters, nodes, supply);
        std::fs::write(out, serde_json::to_string_pretty(&config)?)
            .with_context(|| format!("cannot write {out}"))?;
        println!("generated {out}");
        return Ok(());
    }

    let config_path = flags.get("--config").map(String::as_str);
    let name = flags.get("--name").map(String::as_str);
    let (Some(config_path), Some(name)) = (config_path, name) else {
        usage();
    };

    let config = load_config(config_path)?;
    let genesis_cfg = config
        .genesis()
        .context("genesis configuration is invalid")?;
    let endpoint = config.node(name)?;
    let key = endpoint.keypair().context("missing node key")?;

    // Boot without a certificate first so we can obtain one over the wire.
    let (mut node, genesis) = Node::new(key, &genesis_cfg, None)?;

    let listen = flags
        .get("--listen")
        .map(String::as_str)
        .unwrap_or_default();
    let listen = if listen.is_empty() {
        endpoint.addr.clone()
    } else {
        listen.to_string()
    };

    // Admission from a reachable master.
    let master_addrs: Vec<String> = flags
        .get("--masters")
        .map(|s| s.split(',').map(|x| x.to_string()).collect())
        .unwrap_or_else(|| {
            config
                .masters
                .iter()
                .filter(|m| !m.addr.is_empty())
                .map(|m| m.addr.clone())
                .collect()
        });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for addr in &master_addrs {
        let addr = addr
            .parse()
            .unwrap_or_else(|_| panic!("invalid master address {addr}"));
        match oxydome_node::server::request_admission(
            addr,
            node.public(),
            reference_manifest(),
            now,
        )
        .await
        {
            Ok(Some(cert)) => {
                println!(
                    "admitted by master {} until {} (epoch {})",
                    cert.master.to_hex(),
                    cert.expiry,
                    cert.epoch
                );
                node.admission = Some(cert);
                break;
            }
            Ok(None) => eprintln!("master {addr} refused admission"),
            Err(e) => eprintln!("admission with {addr} failed: {e}"),
        }
    }

    println!(
        "oxydome-node {} listening on {} (height {}, state_root {})",
        name,
        listen,
        node.state.height,
        node.state.utxo_root().to_hex(),
    );
    println!("genesis block hash: {}", genesis.hash().to_hex());

    // Attach durable ledger persistence when requested.
    if let Some(db) = flags.get("--db") {
        let path = std::path::Path::new(db);
        let mut store = oxydome_state::LedgerStore::open(path)
            .with_context(|| format!("cannot open ledger store {db}"))?;
        if store.current_height()?.is_some() {
            anyhow::bail!(
                "ledger store {db} already contains versions; restart replay is not implemented, \
                 use a fresh path"
            );
        }
        store
            .init_genesis(genesis.hash(), &node.state.utxo)
            .with_context(|| format!("cannot seed ledger store {db}"))?;
        node = node.with_store(store);
        let index_store = oxydome_node::index::IndexStore::open(&path.join("wallet-index"))
            .with_context(|| format!("cannot open index store {db}"))?;
        node = node.with_index_store(index_store);
        println!("ledger persistence enabled at {db}");
    }

    oxydome_node::server::run(&listen, node).await?;
    Ok(())
}
