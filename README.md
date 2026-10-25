# avian-sv2

An Avian Stratum v2 pool. Upstream it is a Template Distribution client to
`aviand`, one connection per algorithm. Downstream it is a Mining Protocol
server to workers, one standard channel each. Both halves speak Avian's
`0x4001` extension.

Stages 2 and 3 of `Avian-Native-Stratum-V2-Mining-Plan.md` section 25.

```
crates/avian-pow        Avian's X16RT and MinotaurX, linked from src/algo
crates/avian-tdp        Noise, framing, codecs, the TDP session, coinbase
crates/avian-mining     the Mining Protocol server and the pool wiring
crates/avian-sv2-pool   the binary
crates/avian-regtest    starts a regtest node for tests; test support only
```

**The milestone is reached.** `aviand` to pool to worker to pool to `aviand`,
with a regtest block found by a test worker, relayed by the pool, accepted by
the node, and reported by `getblock` under the algorithm that was negotiated —
for both algorithms. Section 12 of the plan, with the test worker standing in
for a real miner. See [Tests](#tests) for the output.

## Contents

- [The three questions that shaped this](#the-three-questions-that-shaped-this)
- [Building](#building)
- [Running it](#running-it)
- [Tests](#tests)
- [Where doc/sv2.md falls short](#where-docsv2md-falls-short)
- [Design](#design)
- [What is not here](#what-is-not-here)

## The three questions that shaped this

Each stage opened with one question whose wrong answer would have wasted
everything after it. The third is Stage 3's.

### Can the pool compute Avian's proof-of-work hash from Rust? Yes, by FFI

A pool has to compare a share against a target, and for Avian that target is
compared against the X16RT or MinotaurX hash, not SHA256d. Without this,
share validation is a stub and nothing downstream can be verified.

`crates/avian-pow` links Avian's own implementation. It was cheaper than
feared, because the two entry points are header-only templates: `HashX16R` in
`src/algo/x16r/x16r.h` and `Minotaurx` in `src/algo/minotaurx/minotaurx.h`.
Neither needs any of the node's own machinery — only `uint256.h` and the
algorithm sources `src/CMakeLists.txt` already lists, 24 C and C++ files plus
`uint256.cpp`. Nothing is copied into this repository and nothing in the Avian
tree is written to; `build.rs` compiles them in place with the `cc` crate,
which was already in the tree as `secp256k1-sys`'s build dependency.

`ComputePoWHash` itself is not used, because it is a `CBlockHeader` method and
that pulls in `hash.h`, `streams.h` and the rest. The shim instantiates the two
templates directly and derives X16RT's seed, `SHA256d(nTime & 0xffffff80)`,
on the C side so the Rust caller cannot get the mask or the double hash wrong.

It is verified against ground truth rather than against itself: four real
regtest blocks, two per algorithm, taken from `getblock <hash> 0` and
`getblockhash` with `getblock`'s `powtype` saying which algorithm each was
mined under. The hasher reproduces all four block hashes. There is also a test
that the same header hashes differently under each algorithm, so a `pow_type`
argument that was being ignored could not pass.

```
running 3 tests
test tests::the_seed_follows_the_128_second_epoch ... ok
test tests::the_two_algorithms_disagree ... ok
test tests::matches_real_regtest_blocks ... ok
```

`PowHasher` is still a trait, with a `MetadataOnlyHasher` beside the real one.
Not as a fallback — the pool refuses to start without the real hashers — but
because it makes the ordering of the validation ladder testable: a check that
runs *before* the hash can be proved to run before it by using a hasher that
fails. Two of the share tests do exactly that. The stub refuses every share
rather than accepting one, so it cannot be mistaken for a working pool.

### The two from Stage 2

The second one has since been fixed in Avian Core, and this client now runs
entirely on SRI's Noise. Both are recorded because the second is the reason
the spike exists in the shape it does, and part B of it is the regression
guard.

### SRI's codec carries `extension_type = 0x4001` without complaint

This was the question that had to be answered before anything was built. The
answer is yes, unambiguously:

- `framing_sv2::header::Header` holds `extension_type` as a plain `u16`.
  `MessageFrame::from_message(message, msg_type, extension_type, channel_msg)`
  takes it as a parameter, and `update_extension_type` only ever sets or
  clears bit 15. Nothing anywhere assumes `extension_type == 0`.
- `ext_type_without_channel_msg()` exists precisely so `0xc001` and `0x4001`
  look up the same extension, which is what `AvianJobTimeConstraints` needs.
- `codec_sv2`'s Noise encoder encrypts the 6-byte header as its own AEAD
  operation and then the payload in chunks of 65519, which is exactly what
  `src/sv2/noise.cpp` and `test_framework/sv2.py` do.

Part A of `cargo run -p avian-tdp --example extension_spike` proves it: a
`0x4001` frame and a `0xc001` channel-message frame are encrypted by SRI's
`NoiseEncoder` and decoded by SRI's `NoiseDecoder` with every header field
intact.

### `aviand`'s Noise handshake did not follow the Stratum v2 specification

**Fixed in Avian Core; re-verified here.** Jump to
[the verification](#verifying-the-fix) for what was run after the fix. The
diagnosis is kept because part B of the spike is the regression guard for it,
and because it is the reason this client exists as a second reader at all.

Running the spike against a real node turned up a blocker that had nothing to
do with the extension. **SRI's `noise_sv2` could not complete a handshake with
`aviand`**, and the reason was one hash.

Stratum v2, [04-Protocol-Security.md][spec] section 4.5.1.1, has the initiator
do four things in handshake act 1:

> 2. generates ephemeral keypair `e`, appends `e.public_key.serializeEllSwift()`
>    to the buffer
> 3. calls `MixHash(e.public_key)`
> 4. calls `EncryptAndHash()` with empty payload and appends the ciphertext to
>    the buffer (note that *k* is empty at this point, so this effectively
>    reduces down to `MixHash()` on empty data)

Step 4 adds no bytes to the wire and one `MixHash` to the transcript. The
responder's step 4 is the matching `DecryptAndHash()`.

`aviand` omitted it. `HandshakeState::WriteMsg1` in `src/sv2/noise.cpp` was:

```cpp
GenerateEphemeral(m_ephemeral, m_ephemeral_pub);
std::copy(m_ephemeral_pub.begin(), m_ephemeral_pub.end(), out.begin());
m_state.MixHash(out);
```

and `ReadMsg1` matched, so the node was self-consistent and interoperated with
`test_framework/sv2.py`, which omitted it too. It did not interoperate with
anything that follows the specification. That is the failure mode a second
implementation exists to catch: both of Avian's own readers agreed with each
other and with nothing else, and the node's own test suite could not tell.

The chaining key is unaffected, because `MixKey` does not read `h`. Only `h`
diverges, and `h` is the AEAD associated data, so the first decryption in
handshake message 2 fails its MAC check. Observed, with the node's
`-debug=sv2` log showing nothing but `connected` then `disconnected`:

```
B. SRI's noise_sv2 initiator against aviand at 127.0.0.1:18447
   the node answered with all 234 bytes of message 2
   handshake FAILED: NoiseSv2Error(Aead(Error))
```

`codec_sv2`'s Noise encoder and decoder cannot be reused with a handshake from
elsewhere, either: `TransportEncryptState` can only come from
`codec_sv2::Handshake::step_2`, and `noise_sv2::NoiseEngine` has no public
constructor. So while the bug stood, this client carried its own NX state
machine and frame cipher over `chacha20poly1305` and `secp256k1`, with both
readings of act 1 behind a `noise::Variant` flag. All of that is gone.

doc/sv2.md claimed the opposite of what the node did, which is what made the
bug expensive to find:

> The cryptography is the Stratum v2 spec's
> `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256` unchanged.

[spec]: https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md

### Verifying the fix

Avian Core now calls the specification's operations rather than open-coding
`MixHash`: `WriteMsg1` ends with `m_state.EncryptAndHash({}, {})`, `ReadMsg1`
with `m_state.DecryptAndHash({}, {})`, and `sv2.py`'s `msg1()` has the
equivalent.

Against a node rebuilt with that, on a fresh regtest datadir at 101 blocks,
with no authority key supplied so a failure could not be a certificate
problem:

```
B. SRI's noise_sv2 initiator against aviand at 127.0.0.1:18470
   the node answered with all 234 bytes of message 2
   handshake completed: the node's act 1 transcript is the spec's
```

Before the refactor that deleted them, the two `noise::Variant` readings were
run against the same node and came out as the exact inverse of what they had
been:

```
D. the specification's reading of act 1 against aviand
   handshake completed
C. aviand's old reading of act 1: protocol violation: MAC check failed
```

That the old transcript now *fails* is the half worth having. It rules out the
node having become permissive rather than correct: it accepts one transcript,
rejects the other, and the one it accepts is the specification's.

`noise::Variant` and the hand-written `noise.rs` are deleted rather than kept
behind a flag. Nothing was ever deployed against the old transcript, so there
is nothing to be compatible with, and a flag whose wrong setting produces an
unexplained MAC failure is a trap rather than a safety net. Part B of the
spike is the regression guard instead, and it tests the thing that actually
matters — SRI against the node — rather than this client against itself.

## Building

```
cargo build --release
```

Needs Rust 1.75 or later, a C and C++ toolchain, and the Avian Core source
tree. Dependencies are SRI's `codec_sv2`, `noise_sv2`, `framing_sv2`,
`binary_sv2`, `common_messages_sv2`, `mining_sv2` and
`template_distribution_sv2`, plus two that were already in the tree as
transitive dependencies at the versions SRI pins: `secp256k1`, for the
authority keys and for SHA256, and `cc` as a build dependency, to compile
Avian's algorithm sources. Nothing else.

`build.rs` looks for the Avian `src` directory beside this repository, or at
`AVIAN_SRC`. Without it the crate still compiles, but the hashers report
themselves unavailable and the pool refuses to start rather than accepting
every share:

```
AVIAN_SRC=/path/to/Avian-v5.0/src cargo build --release
```

## Running it

Start a regtest node. **Generate a block first:** the node refuses to build
templates while it considers itself in initial block download, and refuses
silently.

```
~/avian-build/bin/aviand -regtest -datadir=/tmp/sv2 -sv2 \
    -sv2powalgo=x16rt -sv2powalgo=minotaurx -debug=sv2 -daemon
~/avian-build/bin/avian-cli -regtest -datadir=/tmp/sv2 createwallet w
ADDR=$(~/avian-build/bin/avian-cli -regtest -datadir=/tmp/sv2 getnewaddress)
~/avian-build/bin/avian-cli -regtest -datadir=/tmp/sv2 generatetoaddress 101 $ADDR
```

With `-sv2` and no `-sv2bind` it listens on `127.0.0.1:18447`.

```
cargo run -p avian-sv2-pool -- --datadir /tmp/sv2
```

That opens one Template Distribution connection per algorithm and then serves
the Mining Protocol on `127.0.0.1:34254`:

```
[pool] generated a new authority key in /tmp/pool-key
[pool] proof of work: Avian's own X16RT and MinotaurX, linked from src/algo
[pool] x16rt: session open, extension 0x4001 accepted, version_rolling_mask 0x00000000, node certificate verified
[pool] minotaurx: session open, extension 0x4001 accepted, version_rolling_mask 0x00000000, node certificate verified
[x16rt] template 1 — the tip moved
[x16rt]   tip 07966e15ab8bf8c1ff4e7b98abbdc3f5fa91f82c6b7fbe4c3ad2bea068f169b4 ntime 1792947890..1792947890
[minotaurx] template 2 — the tip moved
[minotaurx]   tip 07966e15ab8bf8c1ff4e7b98abbdc3f5fa91f82c6b7fbe4c3ad2bea068f169b4 ntime 1792947890..1792947890
[pool] serving the Mining Protocol on 127.0.0.1:34254 for 2 algorithm(s)
[pool] pool authority public key fd19c02f26ae6e3ba3e241e47633238acf0230feeed247d817f4d4b9b2bf8fb0
```

The listener does not open until a template has arrived for every algorithm,
because a worker that connected before one had no target to be given and no
job to mine.

That last line is what a worker pins to know it is talking to this pool. The
pool's authority private key is generated mode 0600 on first run, the same way
the node generates its own.

**Two certificates, two directions.** The pool verifies the node's by default,
from the 32 raw bytes at `<datadir>/regtest/sv2_authority_key`; `--authority
<hex>` takes the key directly for an operator without the node's datadir, and
`--insecure-tofu` skips the check. A worker verifies the pool's, from the
public key above. Noise NX authenticates the server to the client in both
directions and neither client to its server, so it is transport security and
not access control.

Both the connection to the node and the listener are loopback only, and both
refuse anything else.

### The spike

```
cargo run -p avian-tdp --example extension_spike -- /tmp/sv2
```

Three parts: SRI's codec with `0x4001` and `0xc001` between two SRI roles,
SRI's `noise_sv2` initiator against the live node, and real `0x4001` traffic
in both directions. Part B is the regression guard for the Noise act 1 bug,
and it connects without an authority key so a failure cannot be a certificate
problem.

## Tests

```
cargo test
```

43 tests, of which 15 start a real node. Everything that needs one skips with
a message when `aviand` is not found; `AVIAND` and `AVIAN_CLI` override the
default of `~/avian-build/bin`. The nodes the tests start pass `-listen=0`,
without which they bind the regtest P2P port and refuse to start if a node is
already running by hand.

### The milestone

`crates/avian-mining/tests/end_to_end.rs` is section 12 of the plan with a test
worker in place of a real miner:

```
[pool] 127.0.0.1:32970 completed the Noise handshake
[pool] 127.0.0.1:32970 opened channel 1 on x16rt
[pool] channel 1 found a block for template 1, submitting
[test] x16rt mined block 0e5fd7d85ec63ab0b4498c820c17219ef5e5ddd048ad49e9234a1b56217fcf10 at height 102
[pool] 127.0.0.1:32978 completed the Noise handshake
[pool] 127.0.0.1:32978 opened channel 2 on minotaurx
[pool] channel 2 found a block for template 4, submitting
[test] minotaurx mined block 74f14ca9fd22b9fdeaf494abe2bef078cafd07cd0a9a14bee4fd2948031bc624 at height 103
```

The node accepted both and `getblock` reports the algorithm each channel had
negotiated, which the test asserts. Nothing about that is mocked: a real
`aviand` issued the templates, the pool built the coinbases, the worker found
the nonces by hashing, and the node validated the blocks.

### The test worker

`crates/avian-mining/tests/common/worker.rs`, a subdirectory so cargo does not
build it as a product. It opens a channel, receives jobs, searches nonces and
submits shares, and it is a second reader of the pool's wire format, which is
the only way to find out whether the pool's ordering and flags are what it
believes they are.

It records every message **in the order it arrived**, because the properties
worth asserting here are orderings. Asserting that `ntime_min` equals the
activating `ntime_start` passes whatever order the two messages arrived in; the
rule doc/sv2.md states is about order:

```
test constraints_precede_the_set_new_prev_hash_that_activates_a_job ... ok
test the_first_job_on_a_channel_is_a_future_job ... ok
test the_activation_ntime_equals_the_jobs_ntime_min ... ok
```

And the flags, which are silent when wrong:

```
test a_version_rolling_request_is_refused_rather_than_answered ... ok
test setup_success_always_sets_fixed_version_and_never_extended_channels ... ok
test a_worker_that_cannot_take_standard_jobs_is_refused ... ok
test the_extension_is_required_of_a_worker_too ... ok
test the_algorithm_reply_reports_a_zero_version_rolling_mask ... ok
```

And the refusals, each of which a worker could otherwise mistake for silence:

```
test a_rolled_version_or_an_out_of_window_ntime_is_refused ... ok
test a_duplicate_share_is_refused ... ok
test a_share_below_the_network_target_is_accepted_but_not_submitted ... ok
test each_algorithm_gets_its_own_channel_and_job_stream ... ok
```

### The upstream half on its own

`crates/avian-sv2-pool/tests/live_node.rs` opens a Template Distribution
session per algorithm with no Mining Protocol involved, and asserts the
algorithm in `version` bits 16-23, that `AvianTimeConstraints` keys to the
same template and agrees with `SetNewPrevHash`, that
`RequestTransactionData` answers, that an unknown template id is refused
rather than disconnected, and that a tip change pushes fresh work.

## Where doc/sv2.md falls short

This matters because that document is about to be used for a registry
allocation and third-party implementers will build against it.

Findings 1 through 6 are from implementing the **downstream** side, the pool as
a client of the node. Findings 7 through 11 are from implementing the
**upstream** side, the pool as a server to workers, which the document
specifies but nothing in Avian Core implements, so this is the first time
anything has been built against that half.

**All eleven are now resolved**, nine by a change to `doc/sv2.md` or the node,
one withdrawn as wrong, and one, the Noise handshake, by a fix to Avian Core
itself. They are kept here rather than deleted, because the point of the list
is not the defects but the method: both of Avian's own readers of the wire
format agreed with each other and with nothing else, and the node's own test
suite could not tell.

**1. The Noise handshake, above. Fixed in the node; the claim is now true.**
It was the costliest thing in the document, because it was the one claim an
implementer would not think to test: reach for SRI, get a MAC failure with no
diagnostic, and have no reason to suspect the handshake rather than your own
code. Kept here as the record of why this client was worth writing.

**2. `SetNewPrevHash` is documented as conditional and is not. Fixed in the
node: it now follows the tip rather than the refresh.** The document
says:

> `SetNewPrevHash` accompanies a template built on a tip the client has not
> seen. An in-place refresh that picks up new fees sends only `NewTemplate` and
> `AvianTimeConstraints`, so a client must not assume a fixed number of
> messages per round of work.

and builds an argument on it:

> `SetNewPrevHash` is only sent when the tip moved and so cannot be used to
> tell a new-tip round from an in-place refresh

`TemplateProvider::SendTemplate` has no such branch. It sends `NewTemplate`,
`SetNewPrevHash` and `AvianTimeConstraints` unconditionally, every round.
Observed against a node with `-sv2interval=2`:

```
[x16rt] round 1 — the tip moved
[x16rt]     prev_hash      3a89a2e4eb1882d2558ddccc95c1e6ec4823021ae77a740b77d40cf8f121ee7f
[x16rt] round 2 — in-place refresh on the same tip
[x16rt]     prev_hash      3a89a2e4eb1882d2558ddccc95c1e6ec4823021ae77a740b77d40cf8f121ee7f
```

A client written to the documented behaviour still works, since it has to
tolerate the message either way. A client that *relies* on it does not: "a
`SetNewPrevHash` arrived, so the tip moved, so drop every job in flight" is a
reasonable reading of that paragraph and it would throw work away on every
interval refresh. `Work::tip_changed` here compares the hash instead.

Either the document should say the node always sends all three, or the node
should do what the document says.

**3. `SetNewPrevHash`'s third field is named twice. Withdrawn: SRI is the one
that diverges.** I reported this as a documentation defect and it was not one.
Both `05-Mining-Protocol.md` and `07-Template-Distribution-Protocol.md` name
the field `ntime_start`, so the document matches the specification and SRI's
`template_distribution_sv2::SetNewPrevHash::header_timestamp` is SRI's own
name for it. Likewise `stale-template`: `07` defines no values for
`RequestTransactionData.Error.error_code` at all, so the field is free-form and
SRI's `"stale-template-id"` constant is SRI's invention, not a correction.

The thing that is still worth a parenthesis is only that SRI's name differs, so
an implementer wiring SRI's structs to this document has to work out that the
two are one field. That is SRI's problem to fix, not Avian's. The code here
carries the note at the declaration of `PrevHash::ntime_start`.

**4. Three error codes the node sends are not in the document, and one that is
disagrees with SRI. Fixed in the document: the extension's error values are
now tabulated and normative.** The codes the document names are
`unsupported-feature-flags`, `stale-template`, `template-id-not-found`,
`unknown-template`, `bad-algo-id` and `bad-diff`. The node also sends:

| Code | From | Where |
| --- | --- | --- |
| `unsupported-protocol` | `SetupConnection.Error` | `connman.cpp:209` |
| `unsupported-pow-type` | `AvianSelectAlgorithm.Error` | `connman.cpp:353` |
| `algo-already-selected` | `AvianSelectAlgorithm.Error` | `connman.cpp:465` |

The two `AvianSelectAlgorithm.Error` codes are the whole content of a message
the document defines as carrying a `STR0_255` and nothing else, so an
implementer has no way to enumerate them from the document. They belong in the
extension's specification, not just in the node's source, because the
extension is what a registry allocation freezes.

Separately, the node sends `stale-template` while SRI exports
`ERROR_CODE_REQUEST_TRANSACTION_DATA_STALE_TEMPLATE_ID = "stale-template-id"`.
The document matches the node, so SRI is the odd one out, but a client built on
SRI's constants will not match the string it receives. This client accepts
either.

**5. A malformed extension message is a disconnect, not an error reply. Fixed
in the document, along with the error-then-disconnect case beside it.** The
document covers the case where a client never negotiates the extension
("A client that never negotiates at all can only be disconnected, with a log
line and no on-wire explanation"), but not the case where a negotiated
extension message is malformed. Sending `AvianSelectAlgorithm` with a 3-byte
payload gets no `AvianSelectAlgorithm.Error`; the node logs

```
client=6 sent a malformed AvianSelectAlgorithm: sv2: trailing bytes after message
```

and drops the connection. Sending a second, well-formed `AvianSelectAlgorithm`
does get `AvianSelectAlgorithm.Error "algo-already-selected"` — and then the
node drops the connection anyway. That the error reply is immediately followed
by a disconnect is worth stating, because a client that reads the error and
tries to carry on will get an unexplained EOF.

**6. Nothing says how `CoinbaseOutputConstraints` relates to the coinbase a
pool will actually build. Fixed in the document: under-declaring surfaces only
as a refused submission.** The document says the node will not issue a
template before it arrives and that "the coinbase size and sigop budget it
declares are what the block assembler reserves". What it does not say is what
happens if a pool under-declares: the coinbase it then builds fails the
canonical re-serialization check and the submission is refused with nothing on
the wire. One sentence saying the declared size must cover every output the
pool adds, not just its payout, would save an implementer a silent failure.

### From implementing the upstream side

**7. `SubmitShares.Error` has no code for the two things the extension exists
to enforce.** The specification's codes are `invalid-channel-id`,
`stale-share`, `difficulty-too-low` and `invalid-job-id`. An Avian pool must
refuse a share whose `version` differs from the job's, because
`REQUIRES_FIXED_VERSION` is set and rolling bits 16-23 moves the share to the
other algorithm's proof-of-work limit, and one whose `ntime` falls outside
`AvianJobTimeConstraints`. Those are precisely the two failures the extension
was created to make explicit rather than silent, and there is no code for
either.

`error_code` is a `STR0_255`, so inventing one is legal; this pool sends
`invalid-version` and `invalid-ntime`. But a miner cannot know them in advance,
which puts them in the same position the algorithm and the ntime bound were in
before the extension existed. They belong in the extension's own
specification, beside the `AvianSelectAlgorithm.Error` table that was just
added, because they are what a third-party *miner* has to recognise.

**Fixed in the document**, and in the registry submission draft: both
`invalid-version` and `invalid-ntime` are now normative, which is what makes
the names this pool chose recognisable to a miner that did not write them.
This is the mirror image of finding 4 and the same class of defect.

**8. Nothing says what a pool does when a worker clears
`REQUIRES_STANDARD_JOBS`. Fixed in the document: refuse the connection with
`missing-standard-jobs-flag`.** The flag table says Avian v1 wants it — "**1**,
the worker needs `NewMiningJob`" — and explains why, but not what happens if a
worker does not set it. There is no "missing required flag" code:
`unsupported-feature-flags` names flags that *are* unsupported, and the
specification describes the accompanying `flags` field as indicating "which
flag is causing an error", so using it for a flag whose *absence* is the
problem is a stretch a miner cannot disambiguate. The specification has
precedent for a dedicated code in `missing-declare-tx-data-flag`, so an Avian
equivalent would be clearer. This pool refuses with
`unsupported-feature-flags` and the bit named, and a test pins that behaviour
so it is at least consistent.

**9. The `AvianJobTimeConstraints` ordering rules do not cover a tip change.
Fixed in the document: it resolves as the future-job case.**
The document gives two cases, "active job, `ntime_start` present" and "future
job, `ntime_start` absent". Neither is what a pool faces most of the time: a
channel that already has an active job, on a tip that has just moved. Two
readings are defensible. Issue a new *future* job, then its constraints, then
the `SetNewPrevHash` that activates it — which preserves the stated invariant
that constraints precede activation. Or issue an *active* job and a
`SetNewPrevHash`, which arguably breaks it. This pool does the first. One
sentence would settle it, and it is the steady-state case, so it is the one an
implementer will hit most.

**10. "Narrow, never widen" has no floor. Fixed in the document: narrowing to
an empty window is now a protocol error.** A pool must narrow the node's
window. But on regtest and testnet the node pins it shut, `ntime_min ==
ntime_max`, because `nBits` there is a function of `nTime`. A pool that
narrowed a pinned window would produce an empty one and its workers would have
no legal `ntime` at all. The document should say that a pool must not produce
an empty window, or that a pinned one is passed through unchanged. This pool
treats an empty window as a protocol error and refuses to build the job.

**11. Nothing says where the pool's own coinbase outputs may go. Answered in
the document: either order works, and this one needed no experiment.** "What a
client must reproduce" requires every output in `coinbase_tx_outputs` present
verbatim, "with the witness commitment the highest-indexed output bearing the
`aa21a9ed` magic". The pool adds its own payout output and the document does
not say whether that goes before or after the required ones. The natural
implementation — append yours at the end — is the one that looks unsafe, since
it moves the commitment away from the highest index overall. This pool puts the
payout first and the required outputs after it, which works. **I did not test
the other order**, so I cannot say whether it is refused or merely
ill-advised; either way an implementer has to guess, and one sentence would
remove the guess.

## Design

```
avian-pow              Avian's X16RT and MinotaurX, by FFI
avian-tdp::transport   SRI's Noise and framing, both roles, over a socket
avian-tdp::avian       extension 0x4001 and negotiation extension 0x0001
avian-tdp::tdp         the stock Template Distribution messages, owned
avian-tdp::block       coinbase, merkle folding, header, target comparison
avian-tdp::session     one upstream connection, one algorithm
avian-mining::share    the validation ladder, behind a PowHasher trait
avian-mining::job      a job and its ntime window
avian-mining::channel  one standard channel: push work, answer submissions
avian-mining::server   the listener and each worker's session
avian-mining::pool     the wiring, so the binary and the tests share one
```

### The seam between the two halves

A `Connection` splits into a reader and a writer that share no state: each
direction has its own cipher, nonce counter and buffer. That is what makes the
whole thing work with plain threads and no async runtime.

- **Downstream**, the thread that received a template pushes a job onto every
  channel mining that algorithm, while each worker's own thread is blocked
  reading from its socket. Both go through that channel's writer mutex.
- **Upstream**, a worker's thread sends a winning share to the node as a
  `SubmitSolution` through a `SolutionSubmitter`, while the Template
  Distribution session's own thread is blocked in `next_work`.

Holding the writer mutex across a whole round of work is also what keeps it
contiguous on the wire: a `SubmitShares.Success` cannot land between a
`NewMiningJob` and the `SetNewPrevHash` that activates it.

### Decisions worth knowing about

- **Job invalidation compares the prev hash; it does not watch for a message.**
  `aviand` sends `SetNewPrevHash` every round whether the tip moved or not,
  while doc/sv2.md says an in-place refresh omits it, and that is still
  unresolved upstream. `Work::tip_changed` compares the hash, and a channel
  clears its retained jobs only when that is true. A pool keyed on the
  message's arrival would throw away every job in flight on every interval
  refresh; one keyed on its absence would never invalidate against `aviand` at
  all. The comparison is right against both.
- **An `AlgoContext` remembers the prev hash separately from the work**, so a
  round that genuinely omits `SetNewPrevHash` still has a header to build.
  Unreachable against `aviand` today, which is exactly why it is there.
- **Channel ids are pool-wide, not per algorithm.** A channel id goes into its
  coinbase's extranonce, so two channels sharing one would hash identical
  headers whenever their templates matched. A test caught this: two workers on
  different algorithms were handed the same merkle root.
- **The share target is fixed**, the network target made `--share-target-shift`
  halvings harder and then clamped to the worker's `max_target`. No vardiff. On
  regtest the network target is the algorithm's own floor, so the default of 0
  makes nearly every accepted share a block, which is what makes the end-to-end
  test fast.
- **The validation ladder runs every cheap check before the hash.** For Avian
  there is no partial check that can stand in for the hash, which doc/sv2.md
  gives as the reason the node needs a rate limit; the same applies to a pool.
  Two tests prove the ordering by using a hasher that fails.

## What is not here

- No miner. The test worker is test support and says so.
- No payouts, no share accounting beyond what validation needs, no vardiff
  beyond a fixed `SetTarget`, no extended channels, no job declaration, no
  Stratum v1.
- No reconnection. A session that fails reports and stops.
- No rate limiting on submissions. The node has one and the pool relies on
  being loopback; a pool facing untrusted workers would need its own.
- Anything non-loopback.
