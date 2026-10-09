# Oxydome — Implementation Plan

Oxydome is an Ethereum-like blockchain written in Rust. Volunteer **server nodes** keep copies
of the chain and independently re-validate transactions before they are appended to an immutable
ledger. A set of **master nodes** acts as the admission authority and the deep-audit layer: they
verify that a server's software files are unmodified before it joins, and they trace the full
history of funds before co-signing a new block. There is exactly one master at genesis; more
masters are added by a majority vote of the server nodes.

---

## 1. Locked design decisions

| Topic | Decision |
|---|---|
| Hashing | **SHA3-512** (Keccak) for block/tx hashes, Merkle trees, and file manifests |
| Signatures | **Ed25519** for transactions, blocks, admission certificates, and governance votes |
| Consensus | **PoA leader -> master audit + multi-master sign-off -> BFT server commit -> MasterCheck quorum** |
| Master trust root | Genesis master hardcoded in config; further masters admitted by **server-node majority vote** |
| Block append | Requires **2/3+1 master signatures** (audit attestations) **and** BFT commit quorum |
| Money model | Fixed-at-genesis base supply with **governed mint/burn**; value is an **internal unit-of-account index** |
| Mint/burn | Master-only; requires **2/3+1 master approval**; guardrailed |
| Fee split | **4% to masters (split equally)**, **96% to servers (split participation-weighted)** |
| Server withdrawal | Requires **2/3+1 server-node approval**; guardrailed |
| Supply invariant | `sum(live UTXO) == S(t)` where `S(t) = S0 + minted - burned` (minted/burned only via governance) |
| Bunny hop | Invalid transaction via rules BH1/BH2/BH3 (see section 8) |
| Deliverable | Runnable Rust workspace: `node` + `master` binaries, shared crates, tests |

Notes on deviations from the original wording:
- SHA-512 is a **hash**, not encryption. Oxydome uses SHA3-512 **and** Ed25519; a hash alone
  cannot sign transactions.
- "Value rebounds to its previous value" is, by itself, the bunny-hop exploit. To make the bunny
  hop structurally unprofitable, Ox value is an **internal index** (not a redeemable price).
  Holders cannot cash out to an external asset, so rebound gains cannot be arbitraged, and
  rebound-credited coins are locked by maturity (BH1-BH3).

---

## 2. Workspace layout

```
Cargo.toml                    # workspace
crates/
  crypto/     # SHA3-512, Ed25519, Merkle tree, CodeManifest
  core/       # Block, Tx, UTXO, state, validation, conservation
  state/      # authenticated UTXO accumulator (Merkle/MMR), state roots
  audit/      # history tracing, lineage invariant, deep-replay auditor
  currency/   # value index, rebound engine, bunny-hop rules, guardrails
  treasury/   # Mint/Burn governance, multi-master approval
  rewards/    # fee split, node reward accounts (LockedReward), withdrawals
  net/        # framed transport, RTT probe ("nearest master"), wire messages
  consensus/  # PoA leader selection + BFT rounds + master-attestation votes
  master/     # MasterNode: registry/CA, audit attestations, treasury governance
  node/       # Node: chain store, mempool, producer, voter
bins/
  oxydome-master/
  oxydome-node/
config/
  genesis.toml
  node.toml
  guardrails.toml
tests/        # end-to-end: 2 masters + 4 nodes
```

**Storage:** `sled` (pure Rust) for the append-only ledger store and the block log. Every ledger
version is committed atomically (nodes + snapshot + delta) and history can be replayed from an
empty ledger to independently re-derive every state root. (RocksDB is a drop-in upgrade if scale
demands it.)

---

## 3. Data model and supply invariant

The ledger uses a **UTXO** model: conservation is trivial to check and double-spends are naturally
prevented.

- Genesis mints a fixed base supply `S0` (e.g. `1_000_000_000` Ox) into genesis outputs.
- A normal transaction is valid only when `sum(inputs) == sum(outputs) + fee`.
- **Fees are redistributed whole** (masters 4%, servers 96%), never burned, so normal activity
  does not change `S`.
- `S` changes **only** through an approved, guardrailed governance transaction:
  `S(t) = S0 + minted(t) - burned(t)`.
- Every block recomputes `S` and checks the invariant `sum(live UTXO) == S(t)`.
  A mismatch makes the block invalid. This is the literal "agree if the total Ox in circulation
  is the same, otherwise reject" rule.

### Authenticated state root (sparse Merkle tree)

The live UTXO set is committed as the root of a **256-bit sparse Merkle tree** (SMT), the header's
`state_root`. Details:

- Each entry is a leaf at the position `PathKey = first 32 bytes of hash(OutPoint)`; bit `i` of the
  path selects the branch at depth `i` (bit 0 at the root, 0 = left, 1 = right). Leaves live at
  depth 256; the empty subtree commits as `Hash::zero()`.
- The tree is **persistent / functional**: `insert` and `remove` return a *new* version sharing
  unchanged subtrees (`Arc`), so historical versions remain queryable and portable at `O(256)` cost.
- Inclusion is proved with exactly 256 sibling hashes ordered from the leaf level upward
  (`siblings[0]` is the leaf's sibling). The independent builder (`sparse_merkle_root`,
  `sparse_merkle_proof`, `sparse_merkle_verify` in `crypto`) and the ledger implementation agree
  bit-for-bit, cross-checked by tests.
- `sum(live UTXO)` is maintained structurally: every internal node carries `(count, total)`, so
  `total()` is `O(1)` while still validated top-down on load.

### Durable ledger store (sled)

`state::ledger_store::LedgerStore` appends every finalized version to a single sled tree inside
one atomic batch per height:

- `nodes`: every tree node reachable from the version's root, keyed by content-addressed hash
  (immutable, written at most once);
- `snapshots`: `{height, block_hash, root, total}`;
- `deltas`: `{spent, created}`; the genesis delta lists all genesis entries as created so the
  history replays uniformly from an empty ledger;
- a current-height marker.

`verify_history` / `rebuild_from_deltas` replay the entire chain from empty and check each
snapshot's root and total against the recomputed state; `load_ledger(height)` reconstructs any
version and re-verifies every node hash (leaf commitment and internal node hash) plus the root
summary. Server nodes attach the store with `--db <path>` / `Node::with_store` (demo mode uses one
store per node) and persist in `finalize_block` *before* swapping the new head in, so a failed
write leaves the node unchanged and retryable.

### Per-transaction validation pipeline
1. Decode and size bounds.
2. Verify every input's Ed25519 signature.
3. Referenced UTXOs exist and are unspent (no double-spend, including intra-mempool conflicts).
4. Conservation equation, `fee >= 0`, no integer overflow (`u128` internally).
5. Bunny-hop / rebound-maturity rules (section 8).
6. Conflict-free mempool (no two mempool txs spend the same UTXO).

---

## 4. Robust block approval — tracing every transaction

Per requirement, master nodes must account for all funds against the full transaction history
before signing a new block.

### Master data model (resolution of the "no chain copy" conflict)
Master nodes keep **only**:
- the **block header chain** (tiny, one hash-linked header per block),
- the **authenticated UTXO state root** per block, and
- governance/admission registries.

They do **not** store block bodies or the full UTXO set. Full history is verified cryptographically
through state-root proofs plus periodic literal replay (below).

### Block lifecycle
1. **PoA propose.** Only an authorized leader (holding a master-issued admission certificate) may
   propose block `B_h`.
2. **Audit package.** The proposer supplies the block body plus, for every input, a **Merkle proof
   against the previous state root `R_{h-1}`** (existence + unspent), plus the resulting state
   root `R_h`.
3. **Independent master audit.** Each master independently:
   - verifies every input proof against `R_{h-1}` (this cryptographically accounts for the funds
     back through all prior blocks);
   - replays `B_h`, recomputes `R_h'`, and requires `R_h' == header.R_h`;
   - verifies conservation including any `deltaS`, and that the fee distribution sums exactly to `F`;
   - verifies the **lineage invariant** `sum(live UTXO) == S(t)`;
   - verifies the prior header chain / state-root chain is intact;
   - verifies the proposing master/authority is valid for the current epoch.
4. **Deep replay audit (periodic).** At checkpoints every `K` blocks, a randomly chosen master
   requests block bodies for a random range from server nodes and **literally replays from the last
   checkpoint**, comparing the resulting state root. Any divergence rejects the block or slashes the
   offending node.
5. **Multi-master sign-off.** Each master emits
   `AuditAttestation { block_hash, state_root, audit_root, signature }`. A block becomes appendable
   only once **2/3+1 masters** have signed.
6. **Server BFT vote.** Authority server nodes run prepare/commit and finalize at `>= 2f+1`
   (`f = floor((|N|-1)/3)`), and only when both the block QC and the **MasterCheck** quorum exist.

### MasterCheck
In each round every server node signs a `MasterCheck` attesting that (a) the proposing
master/authority is valid for the epoch, and (b) the current master set matches the last
majority-approved set. Blocks finalize only with both the block QC and this quorum.

### Admission and file integrity
- Each binary computes `CodeManifest = MerkleRoot(sorted (path, SHA3-512(bytes)))` over its own
  source/binary files.
- Node -> nearest master: `AdmitRequest { node_pubkey, manifest_root, nonce }`.
- The master checks `manifest_root` is in the approved set and the pubkey is not revoked, then
  issues a signed `AdmissionCertificate`.
- Every peer re-checks the certificate and manifest before the node joins the BFT set.

### Master set growth (1 -> many)
- Genesis config contains exactly one master pubkey.
- A `MasterProposal` requires a **majority of server-node signatures**; existing masters then
  co-sign an epoch transition and the new master joins.
- Masters are ordered by measured round-trip time so nodes connect to the nearest master.

---

## 5. Mint / burn governance and guardrails

- `TreasuryTx { kind: Mint|Burn, amount, target, proposal_id }`.
- Requires one master to propose and **2/3+1 master approval** to execute.
- Guardrails ensure mint/burn never makes low-Ox transactions impossible or costly:
  - hard cap per epoch: `|deltaS| <= epsilon * S0` (epsilon = 0.1%);
  - **value-impact bound**: clamp `deltaS` so `|V_after - V_before| / V_before <= delta`
    (delta = 2%), otherwise reject;
  - **fee-affordability bound**: require `base_fee * V(t)/V0 <= rho * A_min` so small
    transactions stay cheap.
  - Clamp `deltaS` to the largest value satisfying all bounds (the maps are monotone, so the
    boundary is solvable), or reject the proposal.

---

## 6. Fee split, node earnings, and withdrawals

- Block fees `F` are distributed by a `RewardDistribution` transaction whose outputs sum exactly
  to `F` (no minting involved):
  - **masters receive `0.04 * F`**, split **equally** across all masters;
  - **servers receive `0.96 * F`**, split **participation-weighted** (proposer bonus, voters).
- Earnings land as **`LockedReward` UTXOs**: on-chain, counted in `S`, but not freely spendable.
- `Withdraw { node_pubkey, amount }` converts restricted -> spendable and requires
  **2/3+1 server-node approval** with the same guardrails: per-epoch cap `<= kappa * S0` and
  `|deltaV| <= delta`. This keeps withdrawals from jerking the chain and satisfies
  "the Ox the servers make is on the chain."

---

## 7. Ox currency math (internal-index model)

State per window of `W` blocks (e.g. `W = 100`):

- `S` — current supply
- `T` — total transacted Ox in the window (volume)
- `N` — number of transactions; `A = T / max(N, 1)` (mean amount)
- `E` — amount moved into the Exit/Reserve sink (downward pressure)
- `V0 = 1.000` — genesis index; `V_prev` — index at the last positive window
- constants: `alpha, beta in (0,1)`, `gamma`, `eta`, smoothing `lambda`

```
Activity:  Act(t) = 1 + alpha * ln(1 + T(t)/T_ref) + beta * ln(1 + A(t)/A_ref)
Exit:      X(t)   = gamma * (E(t)/E_ref) * (S0/S(t))^eta
Raw:       V_raw  = V0 * (Act(t) - X(t))
Smoothed:  V(t)   = lambda * V_raw + (1 - lambda) * V(t-1)      # lambda ~= 0.1

if V(t) <= 0:
    V(t)   = V_prev            # REBOUND: return to the previous index value
    gen   += 1                 # new rebound generation
    refund Exit/Reserve to depositors, tagging each refunded UTXO with gen
else:
    V_prev = V(t)
```

Properties:
- `V` rises with transaction volume and amounts (the "highest value at runtime under network
  activity"), and is bounded (logarithmic growth).
- `V` is deterministic and recomputed identically by every node each block, so all servers agree
  on the index.
- `S` is not destabilized by mint/burn because section 5 guardrails clamp any supply change.
- Effective fee `= base_fee * V(t)/V0`, paid to the producer; supply is conserved.

All constants live in `config/guardrails.toml` for review and tuning.

---

## 8. Bunny hop = invalid transaction

A "bunny hop" is: withdraw before a rebound, wait for the rebound, then move the refunded Ox out.

**BH1 (maturity):** a UTXO tagged with rebound generation `g` cannot be spent until `L` blocks
after `g` (`L = W`).
**BH2 (provenance):** an account that deposited into Exit/Reserve may not, in the same generation,
transfer rebound-credited UTXOs; the credit stays tainted until matured.
**BH3 (exit + reentry):** a transaction that both sends to Exit/Reserve and receives rebound credits
is rejected outright.

Any transaction violating BH1-BH3 is invalid at validation time and can never enter a block. This
removes the profit path because rebound gains are non-transferable until maturity, and each new exit
resets the generation and lock.

---

## 9. Milestones

- **M0** ~~Workspace scaffolding, config files, `crypto` (SHA3-512 / Ed25519 / Merkle / CodeManifest) + test vectors.~~ **done**
- **M1** ~~`core` (blocks, UTXO, validation, conservation) + `state` authenticated UTXO accumulator.~~ **done**
- **M2** ~~`currency` (index formula, rebound engine, BH1-BH3) + tests (after constant sign-off).~~ **done**
- **M3** ~~`treasury` + `rewards` (mint/burn, fee split, LockedReward, withdrawals, guardrails).~~ **done**
- **M4** ~~`audit` (proof checks, lineage invariant, deep-replay auditor, master attestations).~~ **done**
- **M5** ~~`net` + `master` (admission, code manifests) + `consensus` (PoA leader, BFT, MasterCheck).~~ **done**
- **M6** ~~`oxydome-node` / `oxydome-master` binaries, CLI, end-to-end + property tests, README.~~ **done**
- **M7** ~~Immutable UTXO ledger: 256-bit sparse Merkle tree (`UtxoLedger`), signed `InputProof`s,
  sled `LedgerStore` with atomic per-height commits, history replay/verification, `--db`
  persistence in the node binary and demo.~~ **done**

> **Status (built):** all milestones implemented. `cargo test --workspace` passes 38 tests including the
> end-to-end integration suite (`crates/node/tests/e2e.rs`: admission, PoA production, master audit,
> BFT + MasterCheck finalization, mint/burn/withdraw governance, rejections, and ledger-store
> history verification with a historical genesis proof against the height-0 snapshot). The UTXO set
> is now an immutable 256-bit sparse Merkle tree (`UtxoLedger`); server nodes persist every version
> to a sled `LedgerStore`. `oxydome-node demo --db <path>` boots a 4-master + 4-node network
> in-process, finalizes blocks, and verifies the persisted history through the head. The two
> binaries join a live network: run `cargo run -p oxydome-noded -- init` to generate
> `config/genesis.json`, then launch `oxydome-master` and `oxydome-node` processes; the node is
> admitted over TCP by a master and persists versions when launched with `--db <path>`.
> Note: config files are **JSON** (not TOML) because the `toml` crate cannot serialize `u128` amounts.

---

## 10. Tests

- **Unit:** hash/signature vectors, Merkle/accumulator proofs, conservation, formula monotonicity,
  rebound transition, BH1-BH3 accept/reject.
- **UTXO ledger:** version immutability (older versions untouched by later mutations), in-place
  replace at the same outpoint, incremental root equals the independent `sparse_merkle_root`,
  256-sibling proofs with verification, deterministic path-order iteration, and a 2,000-entry
  perf smoke.
- **Ledger store:** save/load any height, `load_current`, full-history `verify_history` and
  `rebuild_from_deltas`, content-aware deltas for replaced outpoints, reopen-preserves-versions
  (tempdir), missing-version errors.
- **Treasury:** over-cap mint rejected; over-`delta` value impact clamped or rejected; unauthorized
  mint/burn rejected.
- **Audit:** tampered state root rejected; missing/invalid input proof rejected; deep-replay
  divergence detected.
- **Rewards:** `4% / 96%` sums exactly to `F`; unauthorized withdrawal rejected; withdrawal
  guardrail enforced.
- **`proptest`:** random transaction batches never change total supply; no double-spend accepted.
- **Integration (2 masters + 4 nodes):** admit-by-manifest; tampered-manifest node rejected; valid
  tx commits; double-spend rejected; add a third master via server majority; mint via master
  approval; server withdrawal via node approval; volume increase raises `V`; forced exit drives
  `V <= 0` -> rebound; bunny-hop tx rejected; every finalized version replayed and verified from the
  ledger store.

---

## 11. Caveats and trust assumptions

- Literal per-block full-history replay is `O(chain)` and infeasible. Oxydome uses proof-based
  accounting (state-root Merkle proofs) plus periodic literal deep replay, which provides the same
  guarantee without storing block bodies.
- "Server-node majority approves masters" means a 51% server coalition can seat a malicious master.
  This is the documented trust assumption of the chosen model.
- File-hash admission proves **on-disk software** is unmodified; it does not stop a node running
  correct software while lying in protocol — BFT and the audit layer catch that.
- Value never truly going negative is enforced by making it an internal index; a redeemable price
  would reintroduce the bunny-hop arbitrage.

---

## 12. Wallet-Makers API (`walletd`)

An Ethereum-wallet-class developer API for Oxydome: a standalone JSON-RPC 2.0 service (HTTP +
WebSocket) exposing everything a wallet app needs — keys/addresses, balance, UTXOs, coin selection,
fee estimation, tx build/sign/submit, history, confirmation status — plus an optional key vault.
Reference surface is the Ethereum wallet stack (EIP-1474 JSON-RPC, EIP-1193 provider, BIP-39/32 HD
keys), adapted to Oxydome's UTXO + Ed25519 + SHA3-512 model.

### Locked decisions (wallet API)

| Topic | Decision |
|---|---|
| Address display | `ox1…` **bech32m** of the 32-byte Ed25519 pubkey; raw hex kept as an alternate parse/display form |
| Chain queries & history | History / address index lives in the **node**, persisted to sled, shared by all wallet clients |
| Key custody | Default **non-custodial**: the API builds unsigned txs and accepts signed ones (signer is the app). Optional `--vault` starts an AES-256-GCM keystore (BIP-39 mnemonic + SLIP-0010 derivation) so `ox_sendTransaction` works server-side |
| HD derivation | **SLIP-0010** (Ed25519; BIP-32 is secp256k1-only), path `m/44'/ox'/account'/change/index`; coin-type value fixed by config |
| Fee rule | `fee = max(1, ceil(sum(outputs) * 12 / 1_000_000))` — **always 0.0012% of the transaction (output sum) amount**, minimum 1 (zero-fee txs are invalid, `core::tx::validate_structure`) |
| Message signing | **Domain-separated** scheme distinct from tx sighashing (approved spec — see "Message-signing scheme (M10, approved)") |
| Transport | JSON-RPC over HTTP `POST /` (batch supported) + WebSocket `/ws` for subscriptions; EIP-1193-style error codes |

### Architecture

```
Wallet app (browser / mobile / desktop)
      │  JSON-RPC 2.0 (HTTP + WS)
      ▼
oxydome-walletd  bins/oxydome-walletd
  ├─ RPC layer        axum: POST /, GET /health, WS /ws
  ├─ Wallet core      crates/wallet: bech32m addresses, coin selection + change, tx builder,
  │                   fee 0.0012%, signer trait (LocalSigner | RemoteSigner | vault)
  ├─ Optional vault   BIP-39 + SLIP-0010 + AES-GCM keystore (feature-gated)
  └─ Node client      crates/net (extended): query / submit / subscribe
        │  length-framed TCP
        ▼
oxydome-node (existing, extended)
  ├─ read handlers: GetBalance / GetUtxos / GetUtxoProof / GetTx / GetHistory
  ├─ write path:    SubmitTransaction → stateful mempool validation → SubmitResponse
  ├─ pending tracker + Confirmed/Rejected states, event bus (tokio::broadcast)
  └─ persisted history + address index (sled, alongside LedgerStore)
```

### New / changed workspace members

```
crates/
  wallet/               # keys, bech32m addresses, coin selection, tx building, fee (0.0012%), signer trait
  wallet-rpc/           # shared JSON-RPC method/param/result/error + subscription types
  wallet-rpc-client/    # typed Rust client (HTTP + WS) so Rust apps skip hand-rolled JSON-RPC
  net/      (edit)      # new Message variants + Event push frame (node → client)
  node/     (edit)      # read/write handlers, pending tracker, event bus, persisted history index
bins/
  oxydome-walletd/      # axum server binding RPC methods to wallet core over the node client
```

### RPC surface (namespace `ox_`, Ethereum analog in parentheses)

| Group | Methods |
|---|---|
| Chain | `ox_chainId` (eth_chainId), `ox_blockNumber` (eth_blockNumber), `ox_getBlockByNumber/Hash`, `ox_getValueIndex`, `ox_getNodeInfo` (web3_clientVersion) |
| Accounts/balance | `ox_getBalance` (eth_getBalance), `ox_getUtxos`, `ox_getUtxoProof`, `ox_getHistory` |
| Fees/build/send | `ox_estimateFee` (estimateGas), `ox_buildTransaction` → unsigned + per-input `signing_hash`, `ox_sendRawTransaction` (sendRawTransaction), `ox_sendTransaction` (vault only), `ox_getTransactionByHash`, `ox_getTransactionReceipt` (confirmation count/status), `ox_getTransactionStatus` (pending/confirmed/rejected) |
| Signing helpers | `ox_signMessage` / `ox_verifyMessage`, `ox_signTypedData` (scheme per M10 spec) |
| Vault (opt-in) | `ox_accounts`, `ox_requestAccounts`, `ox_vault_createMnemonic`, `ox_vault_importMnemonic`, `ox_vault_deriveAccount`, `ox_vault_listAccounts`, `ox_vault_unlock/lock`, `ox_vault_sign`, `ox_vault_exportPublicKey` |
| Subscriptions | WebSocket `ox_subscribe` / `ox_unsubscribe` (eth_subscribe analog): `newBlocks`, `txConfirmed`, `txFailed`, `balanceChanged(addr)`, `mempool` |

Errors use EIP-1193-style codes mapped into JSON-RPC (`-32601` unsupported method; `-32000..`
domain errors such as `USER_REJECTED`, `INSUFFICIENT_FUNDS`, `NO_SPENDABLE_UTXO`, `FEE_TOO_LOW`,
`INPUT_ALREADY_SPENT`).

### Node / net additions

- `crates/net`: `Message` variants `GetBalance`, `GetUtxos`, `GetUtxoProof`, `GetTx`, `GetHistory`,
  `SubmitTransaction → SubmitResponse{txid, accepted, error?}`, `Subscribe`; push frame
  `Event{kind, payload}` for confirmed/failed txs, new blocks, balance changes, mempool.
- `crates/node`: single-pass `balance(pk)` / `utxos(pk)` helpers over `UtxoLedger::iter()`;
  **stateful** `submit_transaction` (inputs exist + unspent incl. intra-mempool conflicts,
  `fee >= 1`, no dust) with typed errors; bounded mempool; `Pending → Confirmed{height} /
  Rejected{reason}` tracker updated in `finalize_block`; sled-persisted `txid → (height,block,index)`
  and `PublicKey → Vec<TxRef>` index; `tokio::sync::broadcast` event bus driven by submit/finalize.

### Milestones (continues the M0–M7 sequence)

- **M8 — Node read path.** Query messages + handlers; balance/utxos/proof/tx; sled history/address
  index. Node-side tests for each. **done** — all query messages encode/decode, node index persistence via
  sled, handler endpoints (`/balance`, `/utxos`, `/proof`, `/block`, `/tx`, `/history`, `/value_index`,
  `/submit`) return correct types; `NodeClient` helpers (`get_balance`, `get_utxos`, `get_utxo_proof`,
  `get_block`, `get_transaction`, `get_history`, `get_value_index`, `submit_transaction`) functional.
- **M9 — Node write path.** `SubmitTransaction`, stateful mempool validation (`Pending/Confirmed/Rejected`
  tracker), event emission. Property tests: no double-spend, supply unchanged, fee rule enforced. **done**
  — `fee_for_outputs` rule enforced at submit, pending/rejected/mempool inputs tracking, `finalize_block`
  confirms/rejects events, index persistence, fee compliance verified via `build_transfer`.
- **M10 — `crates/wallet` core.** ~~bech32m addresses, signer trait, coin selection + change, tx
  builder, fee 0.0012%, plus the domain-separated message-signing scheme (spec below). Unit +
  `proptest` conservation invariant.~~ **done** — `crates/wallet` builds and passes 36 tests:
  `ox1…` bech32m address with checksum/wrong-HRP/wrong-variant rejection + golden vector, the
  `personal`/`typed-data` signing scheme with cross-domain replay tests + golden vector + RFC-8785
  canonical JSON, the `max(1, ceil(sum(outputs)*12/1e6))` fee rule (overflow-proof), smallest-first
  coin selection with change and a fixed-point fee solver, signer trait, and a `proptest`
  conservation + fee-rule invariant.
- **M11 — `walletd` HTTP JSON-RPC.** All read/write/estimate/build/send methods + error mapping +
  `wallet-rpc-client`. Integration test: build → sign locally → send → confirm → history. **done**
  — `crates/wallet-rpc` (RpcRequest/Response/Error, RpcTransaction/WsNotice conversions, method constants);
  `crates/wallet-rpc-client` (HTTP + WS client with subscribe/unsubscribe); `bins/oxydome-walletd` lib+bin
  (axum `POST /`, `GET /health`, `GET /ws` JSON-RPC router with all `ox_*` methods; vault methods
  return appropriate errors).
- **M12 — WebSocket subscriptions.** `newBlocks`, `txConfirmed`, `txFailed`, `balanceChanged`,
  `mempool`; reconnect/resync semantics; tests. **done** — WS `/ws` endpoint with `ox_subscribe`/`ox_unsubscribe`
  JSON-RPC, `EventHub` with `broadcast::channel(4096)`, node-event listener subscribes to node via
  binary protocol, converts `NodeEvent → WsNotice`, fans out to connected WS clients.
- **M13 — Optional vault.** BIP-39 + SLIP-0010 + AES-GCM keystore + sign endpoints +
  `ox_sendTransaction`. Crypto vectors + lock/unlock tests. **done** — `bins/oxydome-walletd/src/vault.rs`
  (BIP39 mnemonic generation/import, SLIP-0010 Ed25519 derivation via HMAC-SHA512 master/child key,
  AES-256-GCM + scrypt keystore JSON read/write, `VaultHandle` with `create/import/unlock/lock/export/derive_key/sign_hash`);
  `handle_sign_message` and `handle_sign_typed_data` wired; all 7 vault tests pass.
- **M14 — Docs + example.** Method reference, JS/TS example (connect, balance, build, sign in
  browser, send, subscribe) and Rust example via `wallet-rpc-client`.

### Message-signing scheme (M10, approved)

```
message_hash(label, payload) = hash_many(&[ b"ox-sigv1", label, payload ])
                              # crypto::hash_many: SHA3-512 over length-prefixed parts (crypto/lib.rs:125)
```
- Domain labels: `b"personal"` for `ox_signMessage` (signs the raw payload bytes; **not** chain-bound,
  mirrors Ethereum `personal_sign` semantics), and `b"typed-data"` for `ox_signTypedData` (signs
  **RFC-8785 canonical JSON** of the whole request; `domain.chainId` is required, so typed-data
  signatures are chain-bound).
- Ed25519 signs the **64-byte domain digest**, not the raw payload:
  `sig = KeyPair.sign(message_hash(label, payload).as_bytes())`; verification calls
  `crypto::verify(pk, digest, sig)`.
- The tx path is untouched and structurally different (`TxSigningData` bincode-hash over
  `core/tx.rs:117`), so message signatures and input signatures live in disjoint namespaces.
- `SignedMessage { pk, label, payload, sha, signature }` is the on-wire type; `sha` caches the digest.

### Assumptions / notes

- Node should **enforce** the 0.0012% fee at submit time so wallets cannot underpay; confirm during
  M9 (chain-side economics use their own `base_fee * V(t)/V0`, which remains separate).
- Ed25519 signatures are **not** recoverable, so verify-flows always take an explicit public key /
  address (no `ecrecover`).
- Address + history indexing start with `OxydomeScan` + the node index; move to a per-pubkey sled
  index only if account scale demands it.
