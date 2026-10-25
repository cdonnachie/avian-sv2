# Avian Native Stratum V2 Mining Plan

## 1. Objective

Implement native Stratum V2 mining for Avian across the full mining stack while preserving compatibility with the existing Stratum V1 ecosystem.

The target architecture is:

```text
Avian Core / aviand
        |
        | Stratum V2 Template Distribution Protocol
        |
        v
Avian SV2 Pool
        |
        | Stratum V2 Mining Protocol
        |
   +----+-------------------+
   |                        |
   v                        v
MinotaurX Miner          X16RT Miner
CPU                      GPU
```

Avian's two proof-of-work algorithms remain independent. A miner or mining system can mine both X16RT and MinotaurX simultaneously by maintaining a separate SV2 connection for each algorithm.

The first implementation should prioritize correctness, protocol interoperability and clean separation of responsibilities over adding every optional Stratum V2 feature.

---

# 2. Design Principles

The implementation should follow several rules from the beginning.

### Keep `aviand` a node

`aviand` should provide the Stratum V2 Template Distribution Protocol but should not become a pool.

Responsibilities:

```text
aviand
    block construction
    transaction selection
    consensus rules
    PoW targets
    founder payment
    template generation
    block submission
```

The separate pool handles:

```text
pool
    worker management
    share difficulty
    share accounting
    payouts
    SV2 Mining Protocol
```

### Keep algorithms isolated

One SV2 mining connection represents one Avian PoW algorithm.

```text
Connection A
    algorithm = X16RT

Connection B
    algorithm = MinotaurX
```

Do not multiplex the two algorithms through a single mining connection in version 1.

This keeps:

```text
nBits
target
ntime constraints
jobs
shares
difficulty
```

unambiguous.

### Preserve Stratum V1

Existing Avian pools and miners must continue to work.

Native SV2 should be an additional option, not a mandatory migration.

---

# 3. Target Components

The project consists of five major pieces, built in this order.

```text
1. aviand SV2 Template Provider

2. Avian SV2 pool

3. libavian-sv2 shared client library

4. MinotaurX native SV2 miner

5. X16RT native SV2 miner
```

The library is third rather than last. Both miners link it rather than each
carrying its own protocol code, which is what keeps the Noise implementation
count at one. Section 15 has the reasoning.

A sixth optional project can combine both miners into one executable after the individual implementations are stable.

---

# 4. Phase 1: Complete the `aviand` Template Provider

**Status: done.** Implemented on branch `feat/sv2-template-provider` in
`AvianNetwork/Avian`, under `src/sv2/`. `doc/sv2.md` in that branch is the
authoritative wire specification and is what the rest of this plan should be
read against. Where this document and that one disagree, that one is right.

The Template Provider exposes:

```text
SetupConnection
RequestExtensions

AvianSelectAlgorithm

CoinbaseOutputConstraints

NewTemplate
SetNewPrevHash

AvianTimeConstraints

RequestTransactionData
SubmitSolution
```

The Avian extension handles:

```text
pow_type
ntime_min
ntime_max
version rolling restrictions
```

Development uses the experimental extension identifier:

```text
0x4001
```

A production registry allocation is required before mainnet release.

### What the node refuses

The node validates a submission cheapest check first and rejects on every
field check before it will compute a proof-of-work hash. That ordering is a
security property rather than an optimization, because X16RT and MinotaurX
have no cheap partial form: one attacker frame must not buy one hash.

The practical consequence for the pool is that a submission is refused, with
nothing sent back, if the coinbase it built does not match what the template
said. Section 6 lists that contract.

### Algorithm selection

An incoming Template Provider connection selects either:

```text
X16RT
```

or:

```text
MinotaurX
```

That choice is immutable for the lifetime of the connection.

Internally it maps directly to:

```cpp
BlockCreateOptions::pow_type
```

### Result

At the end of this phase:

```text
aviand
   |
   +--- SV2 X16RT template stream
   |
   +--- SV2 MinotaurX template stream
```

should be functional on regtest.

Both algorithms should successfully produce and submit blocks through the Template Provider.

---

# 5. Phase 2: Build a Minimal Avian SV2 Pool

The next component should be a deliberately small reference pool.

It does not initially need:

```text
database accounting
web dashboard
PPLNS
PPS
user management
large-scale clustering
```

Its purpose is to connect:

```text
aviand TDP
```

to:

```text
SV2 Mining Protocol
```

## Pool architecture

```text
                   aviand
                     |
            Template Distribution
                     |
                     v
              avian-sv2-pool
                /          \
               /            \
          X16RT jobs     MinotaurX jobs
              |               |
              v               v
          GPU miners       CPU miners
```

Internally, the pool should maintain separate algorithm contexts:

```cpp
struct AlgoContext {
    PowType algorithm;
    TemplateProviderSession template_session;
    MiningChannels channels;
    uint256 network_target;
    Template current_template;
};
```

Conceptually:

```text
AlgoContext<X16RT>
AlgoContext<MinotaurX>
```

---

# 6. Pool-to-`aviand` Connections

The pool opens one Template Distribution connection per algorithm.

```text
Pool
 |
 +--- TDP connection #1
 |       AvianSelectAlgorithm(X16RT)
 |
 +--- TDP connection #2
         AvianSelectAlgorithm(MinotaurX)
```

Each receives its own:

```text
NewTemplate
SetNewPrevHash
AvianTimeConstraints
```

This also naturally handles Avian's independent per-algorithm difficulty calculation.

## The coinbase contract

With standard mining channels the **pool** builds the coinbase, not the
worker. So these are the pool's obligations to the node, not the worker's to
the pool. The node checks all of them before computing any proof of work, and
a submission that fails one is silently refused:

```text
coinbase_tx_version        exactly as advertised
coinbase_tx_locktime       exactly as advertised
coinbase_tx_input_sequence exactly as advertised

one input, null prevout
scriptSig 2 to 100 bytes, starting with coinbase_prefix
    (coinbase_prefix is the BIP34 height push)

vin[0] witness stack = exactly one 32-byte zero item
    (the BIP141 reserved value)

every output in coinbase_tx_outputs present verbatim
witness commitment is the highest-indexed output bearing aa21a9ed
output total <= coinbase_tx_value_remaining + required outputs
canonical encoding: the node re-serializes and byte-compares
```

Two of those are stricter than consensus deliberately. Avian checks the
**founder payment** only in `ConnectBlock`, not in `ContextualCheckBlock`, so
a pool that dropped that output would otherwise produce a block the node
accepts at header level and relays, only for validation to refuse it later.
The witness commitment is the same case.

`coinbase_tx_value_remaining` is **already net of the founder payment**, so do
not subtract it again:

```text
   coinbase value
         |
   +-----+-------------+
   |                   |
founder             remaining
(mandatory)         (the pool controls this)
```

---

# 7. Native SV2 Mining Protocol

The pool should expose the normal SV2 Mining Protocol to workers.

Initial support should focus on standard channels:

```text
SetupConnection

OpenStandardMiningChannel
OpenStandardMiningChannel.Success

SetTarget

NewMiningJob
SetNewPrevHash

SubmitSharesStandard
SubmitShares.Success
SubmitShares.Error
```

Those are the stock messages. Section 8 adds the Avian extension to this flow,
and two things there are easy to get wrong from this list alone:
`RequestExtensions` sits between `SetupConnection` and `AvianSelectAlgorithm`,
and `AvianSelectAlgorithm` goes before `OpenStandardMiningChannel`, not after
the channel opens. Section 8 also fixes the `SetupConnection` flags on both
sides, which is how "standard jobs only, fixed version" becomes enforceable
rather than conventional.

Extended channels and Job Declaration can come later.

The initial goal is simply:

```text
SV2 miner
     |
     | native SV2
     |
     v
AVN SV2 pool
```

with no Stratum V1 translation.

---

# 8. Avian Mining Extension

The same Avian extension is used on both links. It is `0x4001` on the Template
Distribution Protocol and `0x4001` on the Mining Protocol, negotiated the same
way through extension `0x0001`. `doc/sv2.md` specifies both halves.

The miner must know which algorithm its connection represents, and it must
know the `ntime` window, because the Mining Protocol has the **same** missing
upper bound that Template Distribution has: a job carries an `ntime_start` but
no maximum permitted `nTime`, so an X16RT worker rolling off the end of a job's
epoch computes the wrong hash function. That is not a node-link problem that
the pool link happens to inherit. It is the same gap appearing twice.

The flow:

```text
SetupConnection
      |
      v
RequestExtensions
      |
      v
AvianSelectAlgorithm
      |
      v
OpenStandardMiningChannel
      |
      v
NewMiningJob
      |
      v
AvianJobTimeConstraints
```

`AvianSelectAlgorithm` comes before `OpenStandardMiningChannel`, because the
channel's `nominal_hash_rate` and target only mean something once the
algorithm is known.

## Messages reused as-is

`AvianSelectAlgorithm`, `.Success` and `.Error` are connection-scoped and carry
nothing protocol-specific, so the pool reuses them verbatim on the worker link:

```text
0x00  AvianSelectAlgorithm          pow_type U8
0x01  AvianSelectAlgorithm.Success  pow_type U8, version_rolling_mask U32
0x02  AvianSelectAlgorithm.Error    error_code STR0_255
```

## The one message the Mining Protocol needs

`AvianTimeConstraints` (`0x03`) cannot be reused, because it is keyed on
`template_id` and a worker has no templates. The mining form is:

```text
0x04  AvianJobTimeConstraints
          channel_id  U32
          job_id      U32
          ntime_min   U32
          ntime_max   U32
```

A **channel message**, so bit 15 of `extension_type` is set and it appears on
the wire under `0xc001` while still belonging to extension `0x4001`.

Sent after every `NewMiningJob` or `NewExtendedMiningJob`. Both bounds are
**inclusive**.

It is a separate message rather than a reinterpretation of the same field so
that an implementation sitting on both links, which is exactly what a pool is,
cannot confuse a template id with a job id.

`ntime_min` restates the job's `ntime_start`, and that restatement is doing
real work. SV2 says `ntime_start` is the `nTime` at which hashing starts and
that it **is not the consensus minimum**. Avian's `ntime_min` is a lower bound
on what will be accepted, because below it the node refuses the submission.
Same number, different kind of statement, so the extension states the one it
enforces rather than letting a worker read a start value as a rule.

The relationship, which is a useful test invariant:

```text
active job, ntime_start present
    AvianJobTimeConstraints.ntime_min
        MUST equal NewMiningJob.ntime_start

future job, ntime_start absent
    constraints MAY be sent with the job, if the bounds are
    known then, otherwise they MUST be sent immediately
    before the SetNewPrevHash that activates the job

    either way, the ntime_start that SetNewPrevHash supplies
    MUST equal the ntime_min in force for that job
```

Before the `SetNewPrevHash`, not after. A worker must never have an instant in
which a job is active and its `ntime_max` is unknown, because the only safe
thing it could do in that instant is idle:

```text
NewMiningJob                 future job
[AvianJobTimeConstraints]    optional here, if bounds are known
...
AvianJobTimeConstraints      required here if not sent above
SetNewPrevHash               activates the job
```

A worker MUST NOT begin hashing an Avian job until it holds both its
applicable time constraints and its activation information.

**The node link is the other way round, deliberately.** `aviand` sends
`NewTemplate`, then `SetNewPrevHash`, then `AvianTimeConstraints` last. A pool
implements both sides, so it is worth knowing why they differ rather than
assuming one of them is wrong:

```text
pool -> worker    constraints before activation
    a worker activated by SetNewPrevHash must start hashing
    immediately, so constraints arriving after it leave a real
    instant where it is working without knowing when its work
    expires

node -> pool      constraints last
    a pool cannot build a single job until it has the whole
    round anyway: merkle path, required outputs, prev hash and
    window. There is no equivalent instant.
```

Putting the constraints last on the node link buys a terminator. `SetNewPrevHash`
is only sent when the tip moved, so it cannot be used to tell a new-tip round
from an in-place refresh; a fixed final message can. The Python client in the
Avian tree relies on exactly that, and so should the pool's TDP reader.

Both cases have to be handled. SV2 requires the first `NewMiningJob` after a
channel opens to be a future job with `ntime_start` unset, so every connection
meets the second case before it ever meets the first.

**The pool must narrow, never widen.** Derive the job window from the
`AvianTimeConstraints` the node sent for the template the job came from. The
node will refuse a solution outside its own window, so a worker told it has
more room than the node allows will mine work that cannot be submitted. If a
job is held open across a template refresh, re-send this message with the new
bounds.

`AvianJobTimeConstraints` applies to extended channels too, unchanged: a job's
`ntime` window does not depend on who assembles the coinbase.

Extended-channel coinbase reconstruction, and how Avian's coinbase contract is
enforced across it, are **deferred** until extended channels are implemented.
Do not assume it falls out of the standard-channel case. SV2 defines
`coinbase_tx_prefix` and `coinbase_tx_suffix` **without** the BIP141 marker,
flag and witness data, while Avian's node-side contract requires a specific
witness stack and a canonical byte-for-byte reconstruction. Those two have to
be reconciled deliberately.

## Flags on an Avian mining connection

Version rolling is a negotiated feature with a flag on **each** side, so saying
it is "disabled" is not a contract. The two roles set different flags, in
different messages.

Set by the **miner**, in `SetupConnection.flags`:

```text
bit 0  REQUIRES_STANDARD_JOBS     = 1   worker needs NewMiningJob
bit 1  REQUIRES_WORK_SELECTION    = 0   no Job Declaration
bit 2  REQUIRES_VERSION_ROLLING   = 0   must not demand rolling
```

Set by the **pool**, in `SetupConnection.Success.flags`:

```text
bit 0  REQUIRES_FIXED_VERSION     = 1   version field is not negotiable
bit 1  REQUIRES_EXTENDED_CHANNELS = 0   standard channels are the only kind
```

`REQUIRES_STANDARD_JOBS` matters because without it a standard channel may be
served grouped or extended jobs. A worker that can only process `NewMiningJob`
has to advertise that.

On the node link the same thing is settled differently: `aviand` reports
`version_rolling_mask = 0` in `AvianSelectAlgorithm.Success` and has no option
to change it, because there is no durable safe subset of `nVersion` to open.
Bits 16-23 are the algorithm, bits 29-31 are `VERSIONBITS_TOP_MASK` which Avian
also uses to signal assets, and the rest is BIP9 deployment space where bits 2,
11, 12 and 28 are assigned and the next deployment will take another. So the
pool receives a mask of 0 and passes a fixed version down, and version rolling
is absent on both links rather than merely defaulted off.

`REQUIRES_FIXED_VERSION` is the enforceable half of "no version rolling", and
there is a catch worth knowing. The specification says that if the miner set
`REQUIRES_VERSION_ROLLING` then the pool **must not** set
`REQUIRES_FIXED_VERSION`. The two are mutually exclusive, not one overriding
the other. An Avian pool cannot honour rolling at all, so a miner that demands
it has to be **refused** with `SetupConnection.Error`. Setting the response
flag anyway is not an option the spec allows, and answering without it would
leave the miner believing it may roll.

Note the asymmetry with the node link: Template Distribution defines no flags
at all, so `aviand` rejects any non-zero `SetupConnection.flags` with
`unsupported-feature-flags`.

## Two things the protocol cannot enforce for the pool

```text
1. SetTarget's 32-byte target is compared against Avian's
   proof-of-work hash, X16RT or MinotaurX, not SHA256d.
   This is why SetTarget needs no Avian field, and also why
   no unmodified SV2 miner can work here.

2. The pool builds the coinbase, so section 6's coinbase
   contract is the pool's obligation to the node.
```

## The version 1 contract in one place

```text
one connection            = one algorithm, immutable
one channel type          = standard
one job type              = standard job
nVersion                  = fixed, enforced by flags on both sides
ntime                     = explicit inclusive min and max
merkle root               = fixed, the miner does not recompute it
the miner varies          = nonce, and ntime within its window
the pool constructs       = the coinbase
the pool owns             = Avian coinbase compliance, section 6
targets                   = separate per algorithm, never normalized

no job declaration
no extranonce rolling
no version rolling
no extended channels
```

Deliberately restrictive. Every one of those is something that can be relaxed
later from a working base, and several of them are things that would be very
hard to debug if they were all variable at once.

---

# 9. Phase 3: MinotaurX Reference Miner

MinotaurX should be the first native miner implementation.

Recommended starting point:

```text
JayDDee/cpuminer-opt
```

Reasons:

```text
existing MinotaurX support
mature CPU optimizations
existing Stratum networking
portable C/C++ code
widely tested mining architecture
```

The goal should not be to rewrite its hashing code.

Instead:

```text
existing cpuminer-opt
     |
     +--- existing hashing threads
     |
     +--- replace/add network backend
              |
              +--- Stratum V1
              |
              +--- libavian-sv2 over its C API
```

The SV2 side is linked, not written. By the time this phase starts,
`libavian-sv2` exists and has been exercised by the pool's own test worker, so
the work here is the adapter between its `AvianMiningJob` and cpuminer-opt's
existing job structures, and nothing protocol-level.

---

# 10. Separate Mining From Protocol Handling

The miner should not make the hashing code understand SV2.

Create an internal neutral job representation.

For example:

```cpp
struct AvianMiningJob {
    uint64_t job_id;

    PowType pow_type;

    uint32_t version;
    uint256 prev_hash;
    uint256 merkle_root;

    uint32_t ntime;
    uint32_t ntime_min;
    uint32_t ntime_max;

    uint32_t nbits;

    uint256 share_target;
    uint256 network_target;
};
```

Then:

```text
SV1
  |
  +----+
       |
       v
 AvianMiningJob
       |
       +---- hashing engine

SV2
  |
  +----+
```

This avoids duplicating the actual miner.

---

# 11. MinotaurX Worker Flow

The native SV2 flow becomes:

```text
cpuminer-opt
     |
SetupConnection
  (REQUIRES_STANDARD_JOBS, no REQUIRES_VERSION_ROLLING)
     |
SetupConnection.Success
  (REQUIRES_FIXED_VERSION)
     |
RequestExtensions [0x4001]
     |
RequestExtensions.Success
     |
AvianSelectAlgorithm(MINOTAURX)
     |
AvianSelectAlgorithm.Success
     |
OpenStandardMiningChannel
     |
SetTarget
     |
NewMiningJob
     |
AvianJobTimeConstraints
     |
SetNewPrevHash
     |
     v
CPU hashing threads
     |
MinotaurX(header)
     |
share target reached
     |
SubmitSharesStandard
```

`RequestExtensions` is not optional and not an afterthought. Without it the
pool has no way to send `AvianSelectAlgorithm` or `AvianJobTimeConstraints`, so
a miner that skips it gets a connection it cannot mine on.

If:

```text
hash <= pool target
```

submit a share.

If:

```text
hash <= network target
```

the pool also constructs/submits the block to `aviand`.

---

# 12. First End-to-End Milestone

The first significant project milestone should be:

```text
aviand
   |
   | TDP
   v
avian-sv2-pool
   |
   | Mining Protocol
   v
cpuminer-opt-sv2
   |
   | MinotaurX
   v
valid Avian block
```

Run this entirely on regtest first.

Success criteria:

```text
miner connects via SV2
algorithm negotiated as MinotaurX
channel opens
job received
share submitted
block found
pool submits solution
aviand accepts block
getblock reports MinotaurX
```

Once this works, the protocol design is largely proven.

---

# 13. Phase 4: X16RT Reference Miner

After MinotaurX works, port the same SV2 client layer to a GPU miner.

Recommended initial candidates:

```text
JayDDee/suprminer-jdd
```

or:

```text
tpfuemp/ccminer-tpfuemp
```

The choice should primarily depend on which has the cleaner X16RT implementation and networking separation when development begins.

The hashing backend should remain essentially unchanged.

Architecture:

```text
ccminer
   |
   +--- CUDA X16RT implementation
   |
   +--- mining job abstraction
   |
   +--- SV2 client
```

---

# 14. X16RT-Specific Handling

X16RT requires special treatment because its hash chain depends on:

```text
nTime & 0xFFFFFF80
```

Therefore each SV2 job must honor:

```text
ntime_min
ntime_max
```

The miner must never roll `ntime` beyond the advertised range.

Both bounds are **inclusive**, so `ntime_max` is a usable value and the test is
`>`, not `>=`:

```cpp
if (ntime > job.ntime_max) {
    stop_current_job();
    wait_for_new_job();
}
```

The pool should preferably push a replacement job before the boundary is reached.

Note that on **regtest and testnet the window is pinned shut**, meaning
`ntime_min == ntime_max`, because those chains allow minimum-difficulty blocks
and that makes `nBits` a function of `nTime`. Rolling `ntime` at all there can
produce `bad-diff` from a template whose `nBits` was correct when issued. So a
miner developed only against regtest will never exercise its own rolling code.
Test the rolling path against a signet or a private chain that does not set
`fPowAllowMinDifficultyBlocks`, or it ships untested.

On mainnet, `ntime_max` is the minimum of:

```text
X16RT only: (nTime & 0xffffff80) + 127
now + 1350 - sv2timemargin
nTime + sv2ntimeforward
```

1350 seconds is Avian's future-block limit, not Bitcoin's 7200.

---

# 15. Phase 5: Reusable Avian SV2 Client Library

**Build this before the miners, not after them.**

The original ordering was to let both miners reveal which abstractions are
genuinely common and extract afterwards. That is usually the right instinct and
it is wrong here, for one reason: the pool is Rust and the miners are C and
CUDA. Extracting later does not mean refactoring two Rust codebases into one.
It means writing the SV2 client **twice in C** first, Noise included, and then
discovering what they share.

Writing Noise twice is specifically what this project cannot afford. Avian
Core's own Noise implementation was self-consistent, passed every test written
for it, and could not complete a handshake with any conforming Stratum v2
implementation. It took an independent reader to find that, and the symptom was
a MAC failure with no diagnostic. A second and third hand-written Noise, inside
mining software where the feedback loop is a miner that silently earns nothing,
is a worse bet than doing the library first.

```text
libavian-sv2
```

## It is mostly already written

This is not a new project. The pool's `avian-tdp` crate already contains the
framing, the Noise transport, extension negotiation and the Avian extension
codecs, and Stage 3 adds the Mining Protocol message handling. What the library
needs is the downstream half of the mining messages, which the pool's own test
worker will have exercised, plus the part that does not exist yet:

**A C API.** `extern "C"` bindings and a static library, so `cpuminer-opt` and a
ccminer fork can link it without a Rust rewrite. Section 10's neutral
`AvianMiningJob` struct is the right shape for that boundary: the C side sees
jobs and submits shares, and never sees Noise, framing or SV2 types.

The cost of this ordering is a Rust toolchain in the miner build, and
cross-compiling for Windows and macOS miner releases is harder than for Linux.
That is a real cost and it is smaller than the alternative.

Responsibilities:

```text
SV2 framing
Noise transport
SetupConnection
extension negotiation
Avian algorithm negotiation
standard mining channels
job decoding
target handling
share submission
ntime constraints
connection/reconnection logic
```

It must not contain:

```text
X16RT
MinotaurX
CUDA
CPU hashing
```

Those remain miner responsibilities.

Architecture:

```text
                  libavian-sv2
                   /        \
                  /          \
                 v            v
        cpuminer-opt        ccminer
         MinotaurX           X16RT
```

This also provides an integration path for third-party Avian miners.

---

# 16. Phase 6: Simultaneous Dual-Algorithm Mining

Once both miners support SV2 independently, support mining both algorithms on the same system.

There are two approaches.

## Separate executables

Simplest:

```bash
avian-cpuminer \
    --algo minotaurx \
    --url stratum2+tcp://pool:3334

avian-ccminer \
    --algo x16rt \
    --url stratum2+tcp://pool:3333
```

Result:

```text
CPU
  |
MinotaurX
  |
SV2 connection A
  |
  +---------+
            |
         AVN pool
            |
  +---------+
  |
SV2 connection B
  |
X16RT
  |
GPU
```

This should be supported first.

---

# 17. Optional Unified Miner

Later, a single executable could control both.

Example:

```bash
avian-miner \
    --url stratum2+tcp://pool.example:3333 \
    --x16rt-devices 0,1 \
    --minotaurx-threads 12
```

Internally:

```text
avian-miner
    |
    +--- SV2 session #1
    |       algorithm=X16RT
    |       |
    |       +--- GPU 0
    |       +--- GPU 1
    |
    +--- SV2 session #2
            algorithm=MinotaurX
            |
            +--- CPU worker 0
            +--- CPU worker 1
            +--- ...
```

Although the user sees one miner, these remain two logically independent SV2 mining sessions.

---

# 18. What Happens When Either Algorithm Finds a Block

Both algorithms mine the same Avian blockchain.

Therefore:

```text
X16RT finds block
       |
       v
aviand accepts new tip
       |
       +-----------------------+
       |                       |
       v                       v
new X16RT template      new MinotaurX template
```

Likewise:

```text
MinotaurX finds block
       |
       v
new chain tip
       |
       +-----------------------+
```

Both algorithm streams must abandon the previous tip immediately.

The pool therefore needs to invalidate jobs across both algorithm contexts whenever either Template Provider stream announces a new best block.

---

# 19. Important Pool Synchronization Rule

This is an important implementation detail.

Suppose:

```text
X16RT template #100
MinotaurX template #201
```

both reference:

```text
prev_hash = A
```

X16RT finds:

```text
block B
```

The MinotaurX job based on `A` is now stale.

Therefore the pool needs a shared chain-tip coordinator:

```text
             ChainTipCoordinator
                  /         \
                 /           \
        X16RT context    MinotaurX context
```

When either side sees:

```text
prev_hash = B
```

all jobs referring to `A` should be invalidated.

This prevents CPU miners continuing to work on an old MinotaurX job after the GPU side has advanced the chain, or vice versa.

Worth knowing: the node already pushes `SetNewPrevHash` to **every** connected
client when the tip moves, so both of the pool's TDP sessions learn
independently and neither depends on the other. The coordinator is therefore
not there to carry news between the two algorithm contexts. It is there so the
pool invalidates worker jobs the moment either session reports a new tip,
rather than waiting for that algorithm's own session to be serviced.

---

# 20. Difficulty Handling

Do not attempt to normalize the two algorithms into one difficulty stream.

Maintain:

```text
X16RT network target
X16RT share target

MinotaurX network target
MinotaurX share target
```

independently.

For example:

```text
X16RT channel
    network_target_X16RT
    share_target_X16RT

MinotaurX channel
    network_target_MinotaurX
    share_target_MinotaurX
```

The pool's vardiff system should likewise be per algorithm.

---

# 21. Stratum V1 Compatibility

After native SV2 is stable, optionally add an SV1 compatibility layer.

Architecture:

```text
                       avian-sv2-pool
                        /          \
                       /            \
               native SV2           SV1
                  |                  |
                  v                  v
             new miners         old miners
```

This allows the pool itself to use:

```text
aviand ↔ SV2 TDP
```

even while older miners continue using traditional Stratum V1.

SV1 compatibility should not dictate the internal architecture.

The pool's internal representation should remain SV2/template oriented.

---

# 22. Job Declaration

Do not implement Job Declaration initially.

Version 1 should be:

```text
aviand chooses transactions
       |
       v
pool distributes jobs
       |
       v
miner hashes
```

Later:

```text
miner/job declarator
       |
transaction selection
       |
       v
aviand validation
```

could be investigated.

Avian's founder payment and multi-PoW rules make Job Declaration a separate project that deserves its own design and threat model.

---

# 23. Testing Strategy

## What already exists in tree

Do not rebuild these. `feat/sv2-template-provider` has:

```text
src/test/sv2_messages_tests.cpp           codec round-trips, boundary cases
src/test/sv2_noise_tests.cpp              handshake, certificate, tampering
src/test/sv2_transport_tests.cpp          framing, chunk boundaries
src/test/sv2_options_tests.cpp            config parsing and clamps
src/test/sv2_connman_tests.cpp            session state machine
src/test/sv2_solution_check_tests.cpp     one case per rejection reason
src/test/sv2_template_provider_tests.cpp  template serving, rate limits

test/functional/test_framework/sv2.py     a complete TDP client in Python
test/functional/mining_sv2.py             end to end, both algorithms
```

`test_framework/sv2.py` is the thing to reuse. It is a working Noise NX
handshake, framing layer and codec set for every message the node speaks, in
about 500 lines of Python with no dependencies outside the test framework. For
the pool skeleton in Stage 2 it is a faster way to confirm the node's behaviour
than writing Rust against a live node, and it is the reference when the Rust
codecs disagree with something.

## Unit tests

For the pool and miners, cover:

```text
SV2 message serialization
Noise handshake
extension negotiation
algorithm selection
job decoding
target conversion
ntime limits
share submission
connection state
```

## Pool tests

Share and job correctness:

```text
X16RT and MinotaurX connections remain isolated
wrong-algorithm shares are rejected
wrong target is rejected
stale jobs are rejected
cross-algorithm chain-tip changes invalidate jobs
```

The negotiation state machine, which section 8 made contractual and which is
therefore now worth testing in its own right:

```text
miner requesting version rolling is rejected at SetupConnection
miner omitting REQUIRES_STANDARD_JOBS is handled per documented policy
pool always returns REQUIRES_FIXED_VERSION
pool never returns REQUIRES_EXTENDED_CHANNELS
a worker that skips RequestExtensions cannot proceed to AvianSelectAlgorithm
AvianJobTimeConstraints.ntime_min agrees with the active job's ntime_start
a future job's activation ntime_start agrees with ntime_min
the pool narrows the node's window and never widens it
```

Message ordering, which needs its own tests because an implementation can
have every number right and still emit them in an order that leaves a worker
briefly unable to act:

```text
future job sent without constraints:
    AvianJobTimeConstraints MUST arrive before the
    SetNewPrevHash that activates that job

never emit SetNewPrevHash for a job whose constraints
    have not been sent
```

Two of these are worth singling out. A miner that requests version rolling
must be rejected rather than answered, because the tempting implementation is
to answer it and set `REQUIRES_FIXED_VERSION` anyway, which the specification
does not permit. And the ordering tests must be written as ordering tests:
asserting `ntime_min == ntime_start` passes whether the messages arrived in
the right order or not.

## Miner tests

Use known hash vectors for:

```text
X16RT
MinotaurX
```

to ensure the network refactor cannot alter hashing correctness.

Then the client half of the ordering rule:

```text
miner MUST NOT start hashing a job if SetNewPrevHash
    arrives before that job's AvianJobTimeConstraints

miner stops at ntime > ntime_max rather than >=

miner never alters nVersion, whatever the pool sends
```

The first is the counterpart of the pool test above. A miner that starts
anyway will usually appear to work, because a correct pool never produces that
order, so this only fails against a buggy or hostile upstream, which is
exactly when it matters.

## Regtest

Test:

```text
MinotaurX miner finds AVN block
X16RT miner finds AVN block
both miners run simultaneously
X16RT block invalidates MinotaurX job
MinotaurX block invalidates X16RT job
rapid alternating blocks work
reconnect preserves correct algorithm
pool narrows the node's ntime window, never widens it
pool coinbase satisfies section 6, so submissions are not refused
```

What regtest **cannot** test, per section 14:

```text
ntime rolling
X16RT epoch boundary handling
```

Both are pinned shut there, because regtest allows minimum-difficulty blocks.
Use a private chain without `fPowAllowMinDifficultyBlocks`, or those two paths
ship untested.

---

# 24. Repository Strategy

Keep the projects initially separate:

```text
AvianNetwork/Avian
    aviand Template Provider

AvianNetwork/avian-sv2-pool
    reference pool

AvianNetwork/cpuminer-avian
    MinotaurX reference miner

AvianNetwork/ccminer-avian
    X16RT reference miner

AvianNetwork/libavian-sv2
    shared client library, extracted from the pool
    and linked by both miners over a C API
```

This prevents the consensus repository from accumulating pool or miner-specific code.

---

# 25. Recommended Development Order

### Stage 1 — Node (done)

```text
Commit 0   fix BlockCreateOptions IPC issue      merged to main
Commit 1   SV2 data types and codec              done
Commit 2   Noise transport                       done
Commit 3   listener, SetupConnection, lifecycle  done
Commit 4   extension negotiation (0x0001)        done
Commit 5   Avian multi-PoW extension (0x4001)    done
Commit 6   NewTemplate                           done
Commit 7   SetNewPrevHash                        done
Commit 8   RequestTransactionData                done
Commit 9   SubmitSolution and validation ladder  done
Commit 10  functional tests and doc/sv2.md       done
```

All on `feat/sv2-template-provider`. Still open on that branch, none of it
blocking the pool: a `getsv2info` RPC, template cache eviction limits, and a
`-sv2checkblock` option.

### Stage 2 — Pool skeleton

```text
Connect to aviand
negotiate X16RT
receive templates

Connect second session
negotiate MinotaurX
receive templates
```

### Stage 3 — Mining Protocol

```text
SetupConnection            with the v1 flags from section 8
RequestExtensions          0x4001
AvianSelectAlgorithm
OpenStandardMiningChannel
SetTarget
NewMiningJob
AvianJobTimeConstraints    with the job, or immediately before activation
SetNewPrevHash             activates a future job
SubmitSharesStandard
```

The annotation on those last two is not a detail. Section 8 has the full rule,
and a checklist read on its own would suggest the order is always exactly this.

### Stage 4 — Shared library

```text
libavian-sv2
    extract framing, Noise, negotiation and the Avian
    extension from the pool's avian-tdp crate
    add the downstream mining-protocol half
    add a C API over AvianMiningJob
```

Before the miners, not after. Section 15 says why: the pool is Rust and the
miners are C and CUDA, so extracting later means writing the SV2 client twice
in C first, Noise included.

### Stage 5 — MinotaurX

```text
fork cpuminer-opt
link libavian-sv2
mine first MinotaurX block
```

### Stage 6 — X16RT

```text
fork selected ccminer/suprminer
link the same libavian-sv2
mine first X16RT block
```

### Stage 7 — Dual mining

```text
run CPU MinotaurX
+
GPU X16RT
simultaneously
```

### Stage 8 — Compatibility

Add optional:

```text
SV1 downstream support
```

for legacy miners.

### Stage 9 — Production

Freeze the Avian extension wire format, **both halves**: the Template
Distribution messages `0x00` to `0x03` and the Mining Protocol message `0x04`.
`doc/sv2.md` is the document that gets frozen.

Request an official SV2 extension identifier.

Replace:

```text
0x4001
```

with the assigned production identifier.

Then enable mainnet support.

On what the freeze actually costs. A registry allocation covers an
`extension_type`, and the message numbers inside it are Avian's to assign, so
**adding** a message later needs no new allocation: a future `0x05` is a
compatible extension and an implementation that does not know it will not have
negotiated it. What is not free is **changing** `0x00` through `0x04`, because
their field layouts are what third-party pools and miners will have compiled
against. Treat any such change as a new extension version with its own
identifier.

That is the real reason `0x04` is specified now rather than when the pool needs
it. Not to avoid a second allocation request, which would not be needed, but so
that anyone writing `libavian-sv2` sees the whole extension and does not design
around `AvianTimeConstraints` as if it were the general case when it is the
template-side special case.

---

# 26. Definition of Success

The project is complete when the following topology works reliably:

```text
                         aviand
                           |
                  SV2 Template Distribution
                           |
                           v
                     AVN SV2 Pool
                      /        \
                     /          \
             SV2 X16RT        SV2 MinotaurX
                 |                 |
                 v                 v
              NVIDIA              CPU
               GPU
```

with both algorithms mining simultaneously against the same Avian chain.

Either algorithm must be able to find the next block.

When either does:

```text
new AVN tip
    |
    +---- X16RT workers receive new work
    |
    +---- MinotaurX workers receive new work
```

without stale cross-algorithm mining.

The final system should provide:

```text
native encrypted SV2 transport
native multi-algorithm mining
separate per-algorithm targets
future-template support
fast tip switching
CPU + GPU simultaneous mining
legacy SV1 compatibility when required
no dependency on proprietary miner software
```

That would make Avian a particularly interesting SV2 implementation because it would demonstrate the protocol operating natively across **two distinct proof-of-work algorithms at the same time**, rather than simply porting Bitcoin's SHA256d mining model.
