//! Bounded verification scheduling and load-aware concurrency controls.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LoadSnapshot {
    pub cpu_percent: f32,
    pub memory_percent: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub normal_concurrency: usize,
    pub loaded_concurrency: usize,
    pub queue_capacity: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            normal_concurrency: 100,
            loaded_concurrency: 8,
            queue_capacity: 64,
        }
    }
}

impl ResourceLimits {
    pub fn concurrency_for(&self, load: LoadSnapshot) -> usize {
        if load.cpu_percent > 80.0 || load.memory_percent > 75.0 {
            self.loaded_concurrency
        } else {
            self.normal_concurrency
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerificationJob {
    pub txid: [u8; 64],
    pub next_block: bool,
    pub gas_price: u64,
    /// The peer (node) this job is assigned to, if any. `None` means the job
    /// is queued but not yet assigned to a verifier (an "idle" workload).
    pub assigned_peer: Option<[u8; 32]>,
    sequence: u64,
}

impl VerificationJob {
    /// Creates a new verification job with the given block hash, gas price, and next-block flag.
    pub fn new(txid: [u8; 64], gas_price: u64, next_block: bool) -> Self {
        Self {
            txid,
            gas_price,
            next_block,
            assigned_peer: None,
            sequence: 0,
        }
    }

    /// Assigns this job to a verifier peer.
    pub fn assign(&mut self, peer: [u8; 32]) {
        self.assigned_peer = Some(peer);
    }

    /// Marks this job as unassigned (idle queue entry).
    pub fn unassign(&mut self) {
        self.assigned_peer = None;
    }
}

impl Ord for VerificationJob {
    fn cmp(&self, other: &Self) -> Ordering {
        self.next_block
            .cmp(&other.next_block)
            .then_with(|| self.gas_price.cmp(&other.gas_price))
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for VerificationJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub struct VerificationScheduler {
    limits: ResourceLimits,
    queue: BinaryHeap<VerificationJob>,
    /// Current per-peer load (number of assigned jobs). Used to rebalance
    /// workloads when nodes connect/disconnect so that every connected node
    /// keeps a workload and a small idle buffer is maintained.
    peer_load: BTreeMap<[u8; 32], usize>,
    /// Number of jobs currently assigned to peers (in-flight).
    assigned: usize,
    next_sequence: u64,
}

impl VerificationScheduler {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            queue: BinaryHeap::new(),
            peer_load: BTreeMap::new(),
            assigned: 0,
            next_sequence: 0,
        }
    }

    /// Registers a connected peer so it becomes eligible to receive workloads.
    pub fn register_peer(&mut self, peer: [u8; 32]) {
        self.peer_load.entry(peer).or_insert(0);
    }

    /// Removes `peer` from the active set and returns the count of workloads that
    /// were assigned to it (so they can be reassigned by the caller).
    pub fn deregister_peer(&mut self, peer: &[u8; 32]) -> usize {
        self.peer_load.remove(peer).unwrap_or(0)
    }

    /// Rebalances workloads after a peer disconnects.
    ///
    /// All jobs currently assigned to `departed` peers are stripped of their
    /// `assigned_peer` (returned to the idle queue). The scheduler then pushes
    /// idle (unassigned) jobs to connected peers so that every connected node has
    /// at least one workload while keeping a small idle buffer, satisfying the
    /// invariant that connected nodes always have a workload and a few workloads
    /// remain idle.
    pub fn rebalance_after_departure(&mut self, departed: &[[u8; 32]]) {
        let active_peers: Vec<[u8; 32]> = self.peer_load.keys().copied().collect();

        // Drain the entire priority queue so we can mutate and reassign jobs.
        let mut jobs: Vec<VerificationJob> = Vec::with_capacity(self.queue.len());
        while let Some(mut job) = self.queue.pop() {
            if let Some(p) = job.assigned_peer {
                if departed.iter().any(|dp| dp == &p) {
                    job.unassign();
                    self.assigned = self.assigned.saturating_sub(1);
                }
            }
            jobs.push(job);
        }

        if active_peers.is_empty() {
            // Nothing to rebalance; just unassign departed jobs so they stay in queue.
            for job in jobs {
                self.queue.push(job);
            }
            return;
        }

        // Reassign idle jobs to peers, keeping at least `idle_buffer` jobs idle.
        let idle_buffer = self
            .peer_load
            .len()
            .max(1)
            .saturating_sub(1); // at least one idle workload per node group
        let idle_cap = idle_buffer.max(1);
        let mut idle_count = 0usize;
        let mut peer_round = 0usize;

        // Sort by priority so highest-priority idle jobs get assigned first.
        jobs.sort();

        // First pass: keep a small idle buffer, assign the rest.
        let mut deferred: Vec<VerificationJob> = Vec::new();
        while let Some(job) = jobs.pop() {
            let is_idle = job.assigned_peer.is_none();
            if is_idle && idle_count < idle_cap {
                idle_count += 1;
                deferred.push(job);
                continue;
            }
            let mut job = job;
            if is_idle {
                let peer = active_peers[peer_round % active_peers.len()];
                job.assign(peer);
                *self.peer_load.get_mut(&peer).unwrap() += 1;
                self.assigned += 1;
                peer_round += 1;
            }
            self.queue.push(job);
        }
        // Remaining idle buffer jobs stay idle in the queue.
        for job in deferred {
            self.queue.push(job);
        }
    }

    pub fn enqueue(&mut self, mut job: VerificationJob) -> Result<(), VerificationJob> {
        if self.queue.len() >= self.limits.queue_capacity {
            return Err(job);
        }
        job.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.queue.push(job);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<VerificationJob> {
        self.queue.pop()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loaded_resources_reduce_concurrency() {
        let limits = ResourceLimits::default();
        assert_eq!(
            limits.concurrency_for(LoadSnapshot {
                cpu_percent: 81.0,
                memory_percent: 0.0
            }),
            8
        );
        assert_eq!(
            limits.concurrency_for(LoadSnapshot {
                cpu_percent: 0.0,
                memory_percent: 76.0
            }),
            8
        );
    }

    #[test]
    fn scheduler_prioritizes_next_block_then_gas_price() {
        let mut scheduler = VerificationScheduler::new(ResourceLimits::default());
        let make = |next_block, gas_price| {
            VerificationJob::new([gas_price as u8; 64], gas_price, next_block)
        };
        scheduler.enqueue(make(false, 100)).unwrap();
        scheduler.enqueue(make(true, 1)).unwrap();
        scheduler.enqueue(make(true, 10)).unwrap();
        assert_eq!(scheduler.pop().unwrap().gas_price, 10);
        assert_eq!(scheduler.pop().unwrap().gas_price, 1);
    }

    #[test]
    fn verification_job_new_constructs_correctly() {
        let job = VerificationJob::new([1u8; 64], 42, true);
        assert_eq!(job.txid, [1u8; 64]);
        assert_eq!(job.gas_price, 42);
        assert!(job.next_block);
    }
}
