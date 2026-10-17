use oxydome_bridge::cross_chain::ProofCache;
use oxydome_core::Transaction;
use std::time::Instant;

fn main() {
    let transaction = Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        fee: 0,
        ovm_action: None,
        ohm_context: None,
    };
    let txid = transaction.txid();
    let start = Instant::now();
    for _ in 0..1_000 {
        std::hint::black_box(transaction.txid());
    }
    println!(
        "single transaction hash: {:?} for 1000 iterations",
        start.elapsed()
    );

    let cache = ProofCache::new(10_000, 86_400);
    let start = Instant::now();
    for _ in 0..10_000 {
        std::hint::black_box(cache.get(&txid));
    }
    println!("proof cache lookup: {:?} for 10000 misses", start.elapsed());

    let start = Instant::now();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    for _ in 0..1_000 {
                        std::hint::black_box(transaction.txid());
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    println!("four-worker scaling harness: {:?}", start.elapsed());
}
