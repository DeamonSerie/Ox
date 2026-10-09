use std::net::SocketAddr;

fn usage() -> ! {
    eprintln!(
        "usage:
  oxydome-walletd [--listen <addr>] [--node <addr>] [--chain-id <hex>] [--genesis <hex>]"
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
            "--listen" | "--node" | "--chain-id" | "--genesis" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                flags.insert(args[i - 1].clone(), args[i].clone());
            }
            s if s.starts_with('-') => usage(),
            s => positional.push(s.to_string()),
        }
        i += 1;
    }
    (flags, positional)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (flags, _positional) = parse_key_value_args(&args);

    let listen: SocketAddr = flags
        .get("--listen")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:8545".parse().unwrap());
    let node: SocketAddr = flags
        .get("--node")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:8544".parse().unwrap());
    let chain_id = flags
        .get("--chain-id")
        .cloned()
        .unwrap_or_else(|| "0x0".into());
    let genesis = flags
        .get("--genesis")
        .cloned()
        .unwrap_or_else(|| "0x0".into());

    println!(
        "oxydome-walletd listening on {} (node: {}, chain_id: {})",
        listen, node, chain_id
    );
    oxydome_walletd::serve(listen, node, chain_id, genesis).await?;
    Ok(())
}
