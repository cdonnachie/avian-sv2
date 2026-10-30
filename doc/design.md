# avian-sv2: design and verification notes

The long version. [README.md](../README.md) is the short one: what this is,
how to build it, how to run it. This document is why it is shaped the way it
is, what the Stratum v2 specification leaves undefined, what was found while
making it interoperate, and what it deliberately does not do.

An Avian **Stratum v2 solo mining pool**, and **`libavian-sv2`**, the Stratum
v2 library with a C API that it and the miners are built on.

Solo: a miner puts its own payout address in `user_identity` when it opens a
channel, the coinbase pays that address, and consensus pays the miner
directly. The pool never holds anyone's earnings, which is the point — pooled
mining means holding other people's money between a block and a payout, and
solo means never touching it.

The library carries the protocol core and the Mining Protocol client, so a C
or CUDA miner links a static library and a header instead of writing Stratum
v2, Noise included, a second and third time. The pool consumes the same library
as an ordinary Rust crate and adds the two halves a miner never needs: the
Template Distribution client it is to the node, and the Mining Protocol server
it is to workers.

```
crates/avian-sv2        libavian-sv2: Noise, framing, extension codecs,
                        the Mining Protocol client, and the C API
crates/avian-pow        Avian's X16RT and MinotaurX. NOT in the library
crates/avian-tdp        the pool's Template Distribution client and coinbase
crates/avian-mining     the pool's Mining Protocol server and wiring
crates/avian-sv2-pool   the pool binary
crates/avian-regtest    starts a regtest node for tests; test support only
```

**Both milestones are reached.** Blocks mined over an **extended** channel,
with the miner assembling the coinbase from prefix and suffix rather than being
handed a merkle root, for both algorithms, from Rust and from C:

```
[test] x16rt block 5f01b53b8f59f0de343f6ffbe386e75642a4884f639d1f95b6eace12ef4db4ed mined over an extended channel, extranonce 0000000000000000, paying mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS
[test] a C program mined minotaurx block 196221cec74fba690eff112f611fd0ae7565494bfb5472f0e25ca6e87cb8fded at height 103 over an extended channel
```

And the money one, which still holds on both kinds of channel. `aviand` to pool to
miner to pool to `aviand`, with a regtest block found by hashing, relayed by
the pool, accepted by the node, reported by `getblock` under the algorithm
that was negotiated, **and paying the address the miner supplied at channel
open** — for both algorithms, once driven from Rust and once from a C program
that links the static library.

```
[test] x16rt block 5fbd1319084980faa39786601822107f2e5b5b564765910bf002cdda7a371775 paid 2375 AVN to mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS
[test] minotaurx block 5f07e52c559346ac22e5f5eeb2b0714282ece0af892f32dab7f55f0ce63953fa paid 2375 AVN to mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS
```

That the coinbase pays the miner is the only part of solo mining that cannot
be inferred from the protocol working: every protocol assertion would pass
just as happily if the coinbase paid the operator. So it is checked against
the node's own view of the block it accepted.

## Contents

- [Solo mining](#solo-mining)
- [Extended channels](#extended-channels)
- [The four questions that shaped this](#the-four-questions-that-shaped-this)
- [The C API](#the-c-api)
- [Reconnection, and what does not survive it](#reconnection-and-what-does-not-survive-it)
- [Building](#building)
- [Running it](#running-it)
- [Tests](#tests)
- [Where doc/sv2.md falls short](#where-docsv2md-falls-short)
- [Design](#design)
- [What is not here](#what-is-not-here)

## Solo mining

A miner puts its own payout address in `user_identity` when it opens a channel.
The pool turns that into a `scriptPubKey`, puts it in the coinbase, and
consensus pays the miner. Nothing is held, nothing is owed, and there is no
ledger, because there is nothing to keep a ledger of.

### The identity format

`address` or `address.workername`:

```
mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS.bitaxe-1
```

That is the Stratum v1 convention carried into v2, and it is what a miner's UI
labels "User". The label is the operator's to read: it is logged and it never
affects the payout.

The split is on the **first** dot, not the last. No Avian address can contain
one — neither the base58 alphabet nor the bech32 charset includes a dot — so
the first dot is the unambiguous end of the address, and splitting there also
tolerates a dotted label like `address.rig.1`, which splitting on the last dot
would mis-read as an address of `address.rig` and refuse. Noted because the
convention is usually described as splitting on the last dot, and this does
not.

### An address that does not parse refuses the channel

With `OpenMiningChannel.Error`, and **never a fallback**: not a default
address, not a burn address, not the operator's. A miner that mistypes its
address and is quietly mined to somebody else's is the worst thing this
codebase can do, and it would be silent in exactly the way every other problem
found in this project has been silent.

Four codes, so a miner is told what is wrong rather than only that something
is:

| Code | Meaning |
| --- | --- |
| `missing-payout-address` | `user_identity` was empty, or had no address before the label |
| `invalid-payout-address` | not base58 or bech32, wrong length, or the checksum failed |
| `wrong-network-address` | decoded cleanly, for another chain |
| `unsupported-address-type` | a witness version or program length this pool does not pay |

### What it accepts

P2PKH and P2SH by base58, and segwit v0 by bech32. All three are checked
against a real node: the `scriptPubKey` this module derives is compared with
what `getaddressinfo` says the same address means, so a decoding bug is caught
by the node disagreeing rather than by review. There is also a sweep that
mutates every character of a valid address to every other base58 character and
requires all 1,900-odd results to be refused.

Avian's version bytes are **not** Bitcoin's. Mainnet is 60 for P2PKH and 122
for P2SH, where Bitcoin is 0 and 5, and the bech32 prefixes are `avn`, `tavn`,
`tavn4` and `avnrt`. Assuming Bitcoin's here would accept addresses from the
wrong chain.

Segwit v1 and later are refused by version, before the checksum is looked at,
so a taproot user is told their address type is unsupported rather than that
their address is malformed. Both are refusals, so deciding on the version first
costs nothing and says more.

**One case cannot be caught, and it is Avian's doing rather than this code's.**
Testnet, testnet4, signet and regtest all use base58 version 111 and 196, so a
testnet P2PKH address on a regtest pool is indistinguishable from a regtest one
and will be accepted. Only mainnet is separable by version byte. Off mainnet
the bech32 human-readable part is the only reliable network tag, which is why
the bech32 prefix is checked strictly.

### The operator fee

Optional and zero by default, because adding a configurable second coinbase
output now costs nothing and retrofitting coinbase structure once miners depend
on it is disruptive.

```
--operator-fee <address> --operator-fee-bp <hundredths of a percent>
```

The fee truncates down, so rounding never short-changes the miner, and the two
outputs always sum to exactly `coinbase_tx_value_remaining`: a coinbase that
paid out less would silently burn the difference. A fee that rounds to zero
produces no output at all rather than a dust one. The miner's output is first
and the template's required outputs follow, which keeps the witness commitment
the highest-indexed output.

Checked end to end at 2.5%, against the node's own view of the block:

```
[test] worker 2315.625 AVN, operator 59.375 AVN of 2375 AVN
```

Misconfiguration is refused at startup rather than silently ignored: a fee with
no address, an address with no fee, and more than 10000 basis points are all
errors.

### The coinbase tag

`--coinbase-tag`, default `/avian-sv2/`. It goes in the scriptSig after
`coinbase_prefix`, which is the BIP34 height push and which the node requires
the scriptSig to start with.

At most **87 bytes**, and refused at configuration time rather than when the
node rejects the block: the scriptSig limit is 2 to 100 bytes, the height push
is up to 5, and this pool adds 8 bytes of extranonce. Taking the worst-case
height means a tag accepted today cannot start failing years later. Getting
this wrong is otherwise invisible, because the Template Distribution Protocol
has no `SubmitSolution.Error`.

```
--coinbase-tag is 100 bytes and the most that always fits is 87
```

### Submission rate limiting

**Not deferrable, and in scope here**, because a public solo offering is
untrusted workers. The reason is the one doc/sv2.md gives for the node: there
is no cheap pre-filter for Avian's proof of work. SHA256d lets a server check a
few leading bytes before committing to real work; X16RT and MinotaurX have no
such form, so the only way to know whether a submission is valid is to compute
the whole hash. A worker writing nonces as fast as its socket allows costs a
full X16RT or MinotaurX each, and no amount of cheap field checking changes
that.

So the limiter runs **before everything else on a submission, including the job
lookup**. A rate-refused submission costs a mutex and a subtraction.

Two counters, kept apart, as the node keeps `-sv2maxrejects` apart from its own
rate limit:

- a **token bucket on every submission**, because the cost is the hash and a
  valid submission costs exactly as much as an invalid one
- a running total of **invalid** submissions, which drops the channel, because
  a worker that keeps failing has been told something it is not acting on and
  will never find a block

The bucket is sized from the expected share rate rather than from an arbitrary
constant, which a fixed `SetTarget` makes possible: the chance a random hash
meets the target, times the hash rate the worker claimed, times a tolerance for
the fact that shares arrive as a Poisson process and an honest worker will
exceed its mean often over short windows. On regtest that probability is about
a half, which is why nearly every share there is also a block.

`nominal_hash_rate` is **worker-supplied and unverifiable**, so it is clamped
before it is used, and the resulting rate is clamped again by a floor and a
ceiling. A worker claiming a petahash gets the ceiling, not an unlimited
budget. A rate refusal does not count as invalid, because a worker whose only
sin is being fast should not be dropped as if it were sending rubbish.

Tested by flooding, and by checking that an honest worker at the configured
target is never refused: ten minutes of simulated mining at exactly the
expected interval, which is the case that matters for the people using the pool
correctly. The limit is per channel, and a test asserts a flooding worker does
not deny service to another on its own channel.

**Vardiff stays deferred**, and it is deferred *with* this rather than
separately: the honest answer to a worker flooding cheap shares is usually to
raise its target, which is vardiff, and building either alone invites getting
the other wrong.

### The authority key an operator publishes

A miner's configuration takes the pool's authority public key as one opaque
string pasted in, and the two stacks present x-only keys differently. The pool
prints **both**, labelled, rather than guessing:

```
[pool] authority public key, base58 (Stratum v2 miner configuration):
    9c8XJed4dnmErqwfn55BE9hv32YAB6rLhZCdCCb9WSRZnmX8KvA
[pool] authority public key, hex (32-byte x-only):
    c56eaaa66566aff4ea9d2e7da6dd172303d9d41786182343cfe2fda31aa32831
```

The base58 form is `base58check([0x01, 0x00] ++ x-only key)`, 51 characters,
which is what SRI's `key_utils` produces and what a Stratum v2 miner expects.
A test pins it against `key_utils` itself rather than against a hardcoded
string, so it cannot drift into agreeing with only itself, and the C API
accepts either form so a miner does not have to care which an operator
published.

This is a usability detail with a sharp edge: an operator who publishes the key
in a form their miners cannot parse has a pool nobody can connect to, and the
failure arrives as a handshake that never completes.

## Extended channels

The reason is not completeness. On a **standard** channel the pool hands down a
finished merkle root, and the miner can only take its word for what is in the
block: whether the coinbase pays the miner, whether the transactions are what
the pool says. On an **extended** channel the pool hands down the coinbase in
two halves and the miner assembles it, so it can read every output it is
committing to.

For solo mining that verification is the product. "We wrote the miner, so it
will show you" moves the trust rather than removing it, and stops being true
the moment somebody mines Avian with software this project did not write. The
library therefore **defaults to extended**, and the pool serves both: it never
sets `REQUIRES_EXTENDED_CHANNELS`, so a miner that can only do standard
channels still works.

### The deferral that turned out not to apply

doc/sv2.md deferred extended-channel coinbase handling on the grounds that
Stratum v2 defines `coinbase_tx_prefix` and `coinbase_tx_suffix` **without** the
BIP141 marker, flag and witness data, while Avian's node requires a specific
witness stack and a canonical byte-for-byte reconstruction.

Those two requirements never meet, and the reason is that **a merkle root is
built from txids, and a txid excludes witness data**:

```
pool    splits its coinbase around the extranonce, without witness,
        which is what the spec asks for
miner   inserts its extranonce, hashes prefix+extranonce+suffix to a
        txid, folds the merkle path. Never needs the witness.
pool    on a share, reconstructs the whole coinbase including the
        BIP141 witness and submits that
```

`src/sv2/solution_check.cpp` bears that out in source — it takes
`result.coinbase->GetHash()`, which is the txid, and calls
`FoldMerklePath(coinbase_txid, ctx.merkle_path)` — so the canonical check only
ever applies to what the **pool** submits, which the pool controls entirely.
The witness commitment is unaffected by the extranonce because it commits to
the witness root of the other transactions plus the coinbase's own fixed
all-zero witness, and the extranonce lives in the scriptSig.

**Proved against a live node rather than argued.**
`crates/avian-tdp/tests/extended_coinbase.rs` mines a block the extended way
and has the node accept it, for both algorithms, with a **non-empty merkle
path** — a block with only a coinbase would make the fold a no-op and prove
far less:

```
[test] x16rt: mempool transaction eb384600858273205eba8723c9148ab054c8b9e6370613c9003f715052127505
[test] x16rt template 1 with a 1-hash merkle path
[test] x16rt block 40bc7b9457b74ba9156d20d42d8954b961844219282e11cbedcf4f7c646fb4aa accepted, mined from a prefix/suffix split with a 1-hash merkle path
[test] minotaurx block 2e5fda8a308976443ec3794522ec0fc0dc54f27efb266f4e8d65677a05635cb9 accepted, mined from a prefix/suffix split with a 1-hash merkle path
```

So the deferral can be lifted. There was no conflict to reconcile, only two
requirements that look adjacent and never touch.

### What a miner can check

`ExtendedWork`, in the library, carries the two halves, the merkle path and the
extranonce shape. Two questions it can answer that a standard channel cannot:

- `commits_to_script` — is my payout script really in this coinbase? The claim
  a solo miner most needs, because it is the one a dishonest pool would break.
- `path_contains` — is this transaction in my block? In a two-transaction block
  the single merkle sibling *is* the other transaction's txid. In a larger
  block the siblings are interior nodes, so this answers only for those that
  happen to be leaves, which is why it is phrased as a question about the path
  rather than about the block.

Both have a test that asserts the yes **and** the no, because a check that
cannot say no is not a check.

### The scriptSig, recounted

Three claimants and a hard 100-byte ceiling the node enforces: the BIP34 height
push, the operator tag, and the extranonce.

| | bytes |
| --- | --- |
| BIP34 height push, worst case | 5 |
| extranonce, standard channel | 8 |
| extranonce, extended channel | 4 pool prefix + 8 miner |
| operator tag cap | **83** |

The tag cap was 87 while only standard channels existed and the extranonce was
a fixed 8. Extended channels take four more bytes for the pool's prefix, so the
cap **tightens to 83**, derived from the constants rather than asserted:

```rust
pub const MAX_COINBASE_TAG: usize =
    MAX_SCRIPT_SIG - MAX_HEIGHT_PUSH - (EXTENDED_EXTRANONCE_PREFIX + EXTENDED_EXTRANONCE_SIZE);
```

A miner asking for more extranonce than is left after the height push, the
configured tag and the pool's prefix is refused with
`min-extranonce-size-too-large`, rather than given a channel whose every
coinbase the node would reject — which, with no `SubmitSolution.Error`, would
be silent.

### `version_rolling_allowed` is false

On every extended job, to match `REQUIRES_FIXED_VERSION`. Avian keeps the
algorithm in `nVersion` bits 16-23, so rolling them moves the share to the
other algorithm's proof-of-work limit. The client **refuses a job that says
otherwise**, rather than ignoring the permission: a pool offering something
that cannot be honoured safely is a pool to walk away from.

### One implementation of the bytes

The standard-channel coinbase and the extended-channel split are assembled from
the same `Parts`, and the BIP144 witness splice has one implementation used by
both. They cannot disagree about the bytes because there is only one piece of
code that writes them, and a unit test asserts the split and the whole coinbase
produce the **same txid** for several extranonce lengths. If they ever diverged,
a miner would fold a root the node will not reproduce and every share would be
refused for a reason that looks like bad proof of work.

## The four questions that shaped this

Each stage opened with one question whose wrong answer would have wasted
everything after it.

### Can a C program actually use this? Yes, and it mines blocks

Stage 4's question, and the one the whole ordering rests on. The library was
built before the miners precisely so that Stratum v2 and Noise are written
once rather than three times; if the C boundary did not work, that ordering
would have bought nothing.

`crates/avian-sv2/ctest/session.c` is a C miner in the shape a real one would
take: it polls for protocol events, hashes between polls, and submits when it
finds something. It is compiled by a C compiler with `-std=c11 -Wall -Wextra
-Werror`, linked against `libavian_sv2.a` and `libavian_pow.a`, and run against
a live pool backed by a live node. Not a Rust test calling the `extern "C"`
functions: that would be the API talking to itself, which is the same mistake
as a Noise implementation that only ever talks to itself.

```
linked libavian-sv2 0.1.0, hashers available
connected and opened a channel
job 1 generation 1 algo 0 ntime 1792952101..1792952101 nbits 207fffff
  prev_hash     e6bb644ebc0376783984ad498332ffaef3c5c1efaeafa78cd3e93f52882cbb54
  merkle_root   d73b12a907960862bb8869997c0bae737d61140c769aca592b0f995e39451f72
  share_target  0000000000000000000000000000000000000000000000000000000000ffff7f
submitted nonce 2 ntime 1792952101 for job 1
share 1 accepted, 1 so far
forcing a reconnect
reconnected as generation 2
done: a share was accepted and the connection was re-established
```

and the node took the block:

```
[test] a C program mined x16rt block 322a917b7eebadb9ba4469be51db5c7baaba72a1916bb47006f0a8f03449d9a4 at height 102
[test] a C program mined minotaurx block 21b5905e19548a2102da9c6d0ae88e45f8aa5f96dd39a7b736343013223a1dee at height 103
```

That one program also demonstrates the boundary it is there to prove: the
protocol comes from `libavian_sv2.a` and **the hashing comes from somewhere
else entirely**, here `libavian_pow.a`. The library contains no X16RT and no
MinotaurX, and the C program could not work if it did not bring its own.

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

## The C API

`crates/avian-sv2/include/avian_sv2.h`, hand written, and kept honest by the C
program being compiled against it with `-Werror` in CI-equivalent tests. The
boundary is the neutral `AvianMiningJob`: the C side sees jobs and submits
shares, and never sees Noise, framing or a Stratum v2 type.

```c
AvianSv2Client *avian_sv2_client_connect(const AvianSv2ClientConfig *, int32_t *status);
int32_t avian_sv2_client_poll(AvianSv2Client *, uint32_t timeout_ms, AvianSv2Event *);
int32_t avian_sv2_client_submit(AvianSv2Client *, const AvianMiningJob *, uint32_t nonce, uint32_t ntime);
int32_t avian_sv2_client_disconnect(AvianSv2Client *);
void    avian_sv2_client_free(AvianSv2Client *);

int32_t avian_sv2_build_header(const AvianMiningJob *, uint32_t ntime, uint32_t nonce, uint8_t out[80]);
int32_t avian_sv2_meets_target(const uint8_t hash[32], const uint8_t target[32]);
```

Four rules it keeps, because a C caller cannot be made to read Rust docs:

- **No Rust type crosses.** Strings are copied into caller-owned fixed buffers
  rather than handed out as pointers with a lifetime, so nothing allocated by
  the library is freed by the caller except the one opaque handle.
- **No panic crosses.** Every entry point catches one and returns
  `AVIAN_SV2_ERROR`, because unwinding into C is undefined.
- **A null pointer is an error, not a crash**, and freeing null is defined,
  like `free(3)`. There is a test for exactly that.
- **`submit` takes the job, not its id.** See below; this one cost a bug.

`avian_sv2_build_header` assembles the 80 bytes and stops. Hashing them is the
caller's, and having an optimised hasher is the entire reason the caller is a
miner.

### Linking

```
cargo build --release -p avian-sv2
cc -I crates/avian-sv2/include my_miner.c    target/release/libavian_sv2.a -lpthread -ldl -lm -o my_miner
```

The static library carries the whole Rust standard library, so nothing else is
needed beyond libc, libm, libdl and libpthread. The library itself needs **no
Avian source tree**, because it does no hashing — which is also the simplest
demonstration that the split is real.

If you also link `libavian_pow.a`, as the test program does, add `-lstdc++`:
Avian's lyra2, sponge, tiger and `uint256` are C++. That library does need the
Avian sources, found beside this repository or at `AVIAN_SRC`.

**The cost of this ordering, stated plainly for whoever does Stage 5:** the
miner build now needs a Rust toolchain. On Linux that is `rustup` and
`cargo build --release -p avian-sv2`. Cross-compiling for Windows and macOS
miner releases is harder than for Linux and is the real expense. What it buys
is that Noise is written once.

## Reconnection, and what does not survive it

In the library rather than bolted onto the pool, so a miner gets it too. A
miner that stops on a dropped connection is useless and nobody is watching its
logs.

Both directions:

- **Downstream**, `MiningClient::poll` reconnects transparently. A drop
  surfaces as `Event::Disconnected` and the next poll re-establishes and
  reports `Event::Reconnected`.
- **Upstream**, `avian_tdp::ReconnectingSession` does the same for the pool's
  session to the node, and reports `Round::Reconnected` rather than hiding it,
  because the caller has to act on it.

Backoff is exponential, 250ms doubling to 30s, unlimited attempts by default,
and deliberately without jitter so a test can reason about the delays. A pool
with many miners reconnecting at once wants jitter; that belongs at the point
where a deployment has enough miners for it to matter, and is noted in the
code rather than guessed at now.

### Nothing protocol-level survives

Configuration survives. **Everything else is new**, and that is not a
limitation of this implementation, it is what Stratum v2 is: a new Noise
handshake, a new `SetupConnection`, a new `channel_id` and so a new coinbase
extranonce, new `job_id`s from the pool's counter, the pool's accepted-share
counters back at zero, and upstream, new `template_id`s so every template the
pool was holding is unsubmittable.

So both ends discard every job and template across a reconnect. The pool
withdraws the jobs on every channel and its next job per channel is a future
job again. The client clears its jobs and bumps a `generation` counter, which
is on every `MiningJob` and in the C struct.

**That counter is not decoration.** `submit` originally took a `job_id`, and a
test caught the consequence: job ids restart at 1 on a new connection, so a
nonce found for job 1 of the old connection was submitted against job 1 of the
new one — and the pool accepted it, because it was a structurally valid share
for a different job. It happened to be a block. `submit` now takes the whole
`MiningJob` and refuses one from another generation, in Rust and in C alike.
Hashrate in flight across a reconnect is lost, and there is nowhere for it to
go.

A second bug in the same area, also caught by running it: `with_retry` let the
caller signal "do not retry" by returning a different error, which the loop
then dutifully retried. A miner pointed at a pool that does not serve its
algorithm sat in a reconnect loop instead of saying so. The decision now lives
in the loop, keyed on whether the failure can change: a dropped socket is
retried, a refusal or a bad certificate is not. There is a test with unlimited
attempts that would hang forever if that regressed.

## Building

```
cargo build --release
```

Needs Rust 1.75 or later. Dependencies are SRI's `codec_sv2`, `noise_sv2`,
`framing_sv2`, `binary_sv2`, `common_messages_sv2`, `mining_sv2` and
`template_distribution_sv2`, plus two that were already in the tree as
transitive dependencies at the versions SRI pins: `secp256k1`, for the
authority keys and for SHA256, and `cc` as a build dependency. Nothing else.

**The library alone needs no C++ toolchain and no Avian source tree:**

```
cargo build --release -p avian-sv2
```

The pool does, because it has to check shares and so links Avian's own
hashers. `crates/avian-pow/build.rs` looks for the Avian `src` directory
beside this repository, or at `AVIAN_SRC`. Without it everything still
compiles, but the hashers report themselves unavailable and the pool refuses to
start rather than accepting every share:

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
the Mining Protocol on `127.0.0.1:34254`, as a solo pool:

```
avian-sv2-pool --datadir /tmp/sv2     --coinbase-tag '/blockminerz.com solo/'     --operator-fee <address> --operator-fee-bp 100
```

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

108 tests, of which 36 start a real node and one also invokes a C compiler.
Everything that needs a node skips with a message when `aviand` is not found;
`AVIAND` and `AVIAN_CLI` override the default of `~/avian-build/bin`, and `CC`
overrides `cc`. The nodes the tests start pass `-listen=0`, without which they
bind the regtest P2P port and refuse to start if a node is already running by
hand.

### Solo mining, the money path

`crates/avian-mining/tests/solo.rs`. The milestone test reads the coinbase of
the block the node accepted and asserts it pays the miner's address, for both
algorithms. The rest assert the behaviours rather than the units:

```
test a_mined_block_pays_the_address_the_worker_supplied ... ok
test a_malformed_address_refuses_the_channel_and_mines_nothing ... ok
test an_address_for_the_wrong_network_refuses_the_channel ... ok
test the_operator_fee_appears_when_configured ... ok
test a_flood_is_rate_limited_and_an_honest_miner_is_not ... ok
test too_many_invalid_submissions_drops_the_channel ... ok
test a_worker_label_does_not_change_who_is_paid ... ok
test the_coinbase_carries_the_operator_tag ... ok
```

The malformed-address test also asserts the tip did **not** move and that an
honest miner is still served afterwards: a refusal that took the pool down
with it would be a worse outcome than the one it was avoiding.

The wrong-network test re-encodes a known-good regtest key hash under
mainnet's version byte, so the address is checksum-valid and the only thing
wrong with it is the network. Otherwise it would pass for the wrong reason.

### Extended channels

`crates/avian-tdp/tests/extended_coinbase.rs` is the proof the stage opened
with, above. `crates/avian-mining/tests/extended.rs` is the protocol:

```
test a_miner_mines_a_block_over_an_extended_channel ... ok
test the_miner_can_see_what_it_is_committing_to ... ok
test standard_and_extended_channels_are_served_side_by_side ... ok
test version_rolling_is_not_allowed_on_an_extended_job ... ok
test an_extranonce_of_the_wrong_length_is_refused ... ok
test an_oversized_extranonce_request_refuses_the_channel ... ok
```

The visibility test is the one that encodes the product claim: a known
transaction goes into the mempool, and the miner, from nothing but what it was
sent, determines that transaction is in its block and that its own payout
script is in the coinbase, then mines a share the pool accepts, which it could
not do if its reading of prefix and suffix were wrong. **If extended channels
stop giving a miner that, this test fails.**

`standard_and_extended_channels_are_served_side_by_side` keeps the other half
honest: both channel kinds open on one pool, get their own ids and coinbases,
and both mine accepted shares.

### The C program

`crates/avian-mining/tests/c_api.rs` builds both static libraries, compiles
`ctest/session.c` against the hand-written header with `-Werror`, links it, and
runs it against a live pool for each algorithm. It asserts the program got a
channel, had a share accepted, reconnected, and that the node's tip advanced
with the right `powtype`.

```
test a_c_program_mines_a_share_through_the_static_library ... ok
```

It runs three times: extended for each algorithm, and standard once, so both
channel kinds are proved usable from C. On an extended channel it reads back
the coinbase it assembled before mining it:

```
connected and opened an extended channel, paying mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS
  extended: 8 extranonce bytes, a 194-byte coinbase I assembled
```

It is the only test that can catch three things: the header drifting from
`capi.rs` (the compile fails), the documented link line drifting from what
actually links (the link fails), and an API that is awkward or impossible to
use from C (the program cannot be written). The first of those also has a
cheap unit test, `the_c_header_matches_this_module`, which compares the
constants without needing a compiler.

**And a fourth, which compiling cannot catch.** The header is hand written, so a
field added to the Rust side in the wrong place would make every member after
it read the wrong bytes while still compiling. A job whose `ntime` or
`share_target` silently shifted would mine garbage rather than fail, which is
this project's recurring failure shape. `avian_sv2_abi_check` takes `sizeof`
and `offsetof` from the caller and answers before that can happen; the C
program calls it at startup. One offset and one size per struct is enough: the
offset catches a field inserted before it, the size one appended after.

### Reconnection, tested as reconnection

```
test a_miner_reconnects_after_the_connection_drops_and_resumes_mining ... ok
test work_from_before_a_reconnect_cannot_be_submitted ... ok
test the_pool_reconnects_to_the_node_and_resumes_serving ... ok
```

Not a retry counter. The first closes the socket for real — the pool logs
`worker session ended` — and then asserts a **new channel id**, a bumped
generation, a fresh job, and a share accepted on it. The third **stops the
node and starts it again** on the same datadir, and asserts the pool
re-established its session and that work resumed all the way back to the node:
a share on the resumed job is accepted, which can only happen if the pool got a
new template and built a coinbase the node accepts.

### The milestone

`crates/avian-mining/tests/end_to_end.rs` runs the whole path with a test
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

### The miner side of the tests

There is no test worker any more. It was the prototype of the Mining Protocol
client and has been **promoted into the library**, so these tests drive the
product rather than a parallel implementation of it. That is the failure mode a
refactor like this has: quietly stopping exercising what it moved.

The client records every protocol message **in the order it arrived**, exposed
as `MiningClient::trace()`. That is a diagnostic any protocol library should
have — most of what doc/sv2.md requires of a pool is ordering, and a miner
debugging a pool needs to see it — and it is also what these tests assert
against. Asserting that `ntime_min` equals the activating
`ntime_start` passes whatever order the two messages arrived in; the rule
doc/sv2.md states is about order:

```
test constraints_precede_the_set_new_prev_hash_that_activates_a_job ... ok
test the_first_job_on_a_channel_is_a_future_job ... ok
test the_activation_ntime_equals_the_jobs_ntime_min ... ok
```

And the flags, which are silent when wrong:

```
test setup_success_always_sets_fixed_version_and_never_extended_channels ... ok
test the_algorithm_reply_reports_a_zero_version_rolling_mask ... ok
```

The cases that have to send something the library refuses to send — the wrong
`SetupConnection` flags, a `RequestExtensions` without `0x4001` — go straight
at the transport instead, because a product client should not offer a way to
misbehave:

```
test a_version_rolling_request_is_refused_rather_than_answered ... ok
test a_miner_that_cannot_take_standard_jobs_is_refused ... ok
test the_extension_is_required_of_a_miner_too ... ok
```

And the refusals, each of which a miner could otherwise mistake for silence:

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
anything has been built against that half. Finding 12 is from writing the
miner's side, which is the first thing to have worn that shoe. Findings 13 and
14 are from building a solo pool, where `user_identity` stops being a label and
becomes an instruction about money. Findings 15 and 16 are from building
extended channels, which the document had deferred.

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

### From writing the miner's side

**12. Nothing warns that a `job_id` is only unique within a connection.** The
extension specifies the Mining Protocol half carefully, down to the ordering of
`AvianJobTimeConstraints` against `SetNewPrevHash`, but neither it nor the
Stratum v2 specification says anything about identifier reuse across a
reconnect. Both `channel_id` and `job_id` come from a pool's own counters, and
a pool that restarts them — as this one does, and as a reasonable
implementation would — lets a miner holding a nonce for job 1 submit it after
a reconnect against a *different* job 1.

This is not hypothetical: it is a bug this project shipped and a test caught,
and the pool accepted the share, because it was a structurally valid submission
for the job that now held that id. It happened to be a block. The fix is on the
miner's side (`submit` takes the whole job, not its id, and refuses one from an
earlier generation), but a miner author has no way to know the hazard exists
from reading the document.

One sentence in the extension would do it: that a share is only valid on the
connection whose channel issued the job, and that a miner must discard work in
flight when a connection drops. It is the same class of silent failure the
extension was created for — a miner hits none of these as an error, it just
earns nothing or earns someone else's share — which is the argument for it
being in scope rather than left to the Stratum v2 specification.

### From building a solo pool

**13. `OpenMiningChannel.Error` has no code for an unusable payout address.**
The Stratum v2 specification defines `unknown-user` and `max-count-exceeded`,
and neither fits. A solo pool reads `user_identity` as the address it will pay,
so "I cannot read where to send the money" is its single most important
refusal, and it has to invent a code for it. This pool sends
`missing-payout-address`, `invalid-payout-address`, `wrong-network-address` and
`unsupported-address-type`.

`error_code` is a `STR0_255`, so inventing them is legal, but a miner cannot
know them in advance, which is the same position the algorithm and the ntime
bound were in before the extension existed. This is the third instance of the
pattern findings 7 and 8 describe, and the sharpest, because it is the one with
money behind it: a miner that cannot tell "your address is wrong" from "the
pool is full" will retry forever against a pool that will never serve it.

It is arguably more Avian's business than the specification's. Solo mining
makes `user_identity` carry an address, the convention for that is
`address.workername` by observation rather than by any standard, and nothing
says what a pool does when it cannot parse one. If the extension is going to
describe the Mining Protocol half at all, this is worth a paragraph and a code
or two.

**14. Nothing documents the `address.workername` convention.** Not a defect in
doc/sv2.md so much as a gap in what exists anywhere: `user_identity` is a
`STR0_255` and the specification says nothing about structure, while every
miner in the field puts `address.workername` in it because Stratum v1 did. A
pool that did not know that would try to parse the whole string as an address
and refuse every real miner. Worth stating wherever Avian describes what a pool
should do with the field, because it is load-bearing and entirely undocumented.

### From building extended channels

**15. The extended-channel deferral was based on a conflict that does not
exist.** doc/sv2.md deferred the whole thing on the grounds that Stratum v2
defines `coinbase_tx_prefix` and `coinbase_tx_suffix` without the BIP141
marker, flag and witness, while Avian's node requires a specific witness stack
and a canonical byte-for-byte reconstruction, and that the two "have to be
reconciled deliberately rather than assumed compatible".

They never meet. A merkle root is built from txids, a txid excludes witness
data, and `solution_check.cpp` folds the path onto `GetHash()`, the txid. The
canonical check applies only to what the pool submits, which the pool builds
in full. Confirmed against a live node, both algorithms, non-empty merkle path.
The passage can say so, and the registry submission's "deferred" can go.

What *is* worth documenting in its place, and is not anywhere now:

- **A pool must reserve the whole extranonce in the scriptSig length that goes
  inside `coinbase_tx_prefix`.** The length byte is in the prefix, before the
  bytes it counts exist. Getting it wrong produces a coinbase that is malformed
  for every extranonce, and with no `SubmitSolution.Error` the pool would see
  nothing but shares that never become blocks.
- **The scriptSig's 2-to-100-byte bound is shared three ways** on an extended
  channel: the BIP34 height push, the operator tag and the extranonce. A pool
  has to refuse a `min_extranonce_size` it cannot fit rather than grant it, and
  the Stratum v2 specification has no error code for that either, so this one
  sends `min-extranonce-size-too-large`. That is the fourth instance of the
  gap findings 7, 8 and 13 describe.
- **`version_rolling_allowed` must be false**, which the Avian extension
  already implies through `REQUIRES_FIXED_VERSION` but does not say for the
  extended-job message that carries its own flag. A miner should refuse a job
  that sets it, and this client does; saying so would make that a rule rather
  than a choice.

**16. Nothing says what a miner may conclude from `merkle_path`.** The
visibility that justifies extended channels rests on it, and its contents
depend on the block: in a two-transaction block the single sibling is the other
transaction's txid, so inclusion is checkable; in a larger block the siblings
are interior nodes and most are not txids at all. A miner that assumed every
entry was a txid would quietly check nothing. Worth a sentence, because the
whole argument for preferring extended channels is about what a miner can
verify, and this is the limit of it.

## Design

```
libavian-sv2, the lift-out unit:
  avian_sv2::address     Avian addresses, identities, authority keys
  avian_sv2::transport   SRI's Noise and framing, both roles, over a socket
  avian_sv2::avian       extension 0x4001 and negotiation extension 0x0001
  avian_sv2::block       header, SHA256d, merkle fold, target arithmetic
  avian_sv2::wire        the field codecs SRI does not provide
  avian_sv2::authority   the key a certificate is checked against
  avian_sv2::reconnect   backoff, and what does not survive a reconnect
  avian_sv2::client      the Mining Protocol client: what a miner needs
  avian_sv2::capi        the same client over extern "C"

the pool, consuming it as an ordinary Rust crate:
  avian_tdp::tdp         the stock Template Distribution messages, owned
  avian_tdp::coinbase    the coinbase, its prefix/suffix split, payout split
  avian_mining::ratelimit  per-channel submission limits
  avian_tdp::session     one upstream connection, with reconnection
  avian_mining::share    the validation ladder, behind a PowHasher trait
  avian_mining::job      a job and its ntime window
  avian_mining::channel  one standard channel: push work, answer submissions
  avian_mining::server   the listener and each worker's session
  avian_mining::pool     the wiring, so the binary and the tests share one

avian-pow                Avian's X16RT and MinotaurX, by FFI. Pool only.
```

### Where the line is drawn, and why it will feel wrong

`avian-pow` is in this workspace and the library will look incomplete without
it. It stays out. A miner already has hashing, heavily optimised, and that is
the entire reason it is a miner; the library's job is to hand it a job and take
back a share. The split is also what keeps the library's build free of a C++
toolchain and of any Avian source tree at all.

The pool links `avian-pow` because a pool is not a miner: it has to check a
share and has no optimised hasher of its own. The C test program links it for
the same reason a real miner links its own code.

The Template Distribution Protocol is out of the library too, and for a
sharper reason: no miner ever speaks it.

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
- **An extended job carries no merkle root, and that is deliberate.** The
  field is zero and the root is computed from whichever extranonce the miner
  picks. Sending a root the miner would have to ignore would be an invitation
  to use it.
- **The merkle fold lives in the library, not the pool.** It moved there when
  extended channels arrived, because a miner folds the same path onto a
  coinbase it assembled itself. The pool re-exports it, so there is still one
  implementation.
- **`poll` uses a peek, not a read timeout.** SRI's decoder counts the bytes of
  `writable()` as present before they are read, so a `read_exact` that times
  out part way leaves it decrypting whatever the buffer held, with no way back.
  `ConnectionReader::wait_readable` peeks one byte instead, which touches no
  decoder state, so a caller can ask "is there anything?" as often as it likes
  and only then commit to a blocking read. A peer that sends one byte and stops
  still blocks that one connection for its own timeout, which is what the
  timeout is for.

## What is not here

- **No miner.** `ctest/session.c` is a test program and says so; it exists to
  prove the C boundary, not to mine anything. The first native Avian Stratum v2
  miner is the next stage, which means this one ships with no clients.
- **No hashing in the library.** Deliberately, and at length above.
- **No Stratum v1**, and not as an oversight: an SV1 downstream adapter would
  have shaped the pool around a protocol the project is trying to move past.
- No job declaration.
- Anything non-loopback. Both the connection to the node and the Mining
  Protocol listener refuse it.

### Deferred requirements, not out of scope

The pool ships, so these are things it needs and does not have yet, rather
than things it will never have:

- **Share accounting and a payout ledger.** Not needed for solo, by
  construction, and needed the moment pooled mining is offered.
- **Persistence.** Everything is in memory: restart the pool and every channel,
  job and counter is gone. A miner reconnects and carries on, so the cost is a
  moment of lost hashrate rather than lost money, but an operator cannot answer
  a question about yesterday.
- **Vardiff.** The share target is fixed, the network target made
  `--share-target-shift` halvings harder. Deferred *with* rate limiting rather
  than separately, because the two are entangled: the honest answer to a worker
  flooding cheap shares is usually to raise its target.
- **An operator view.** Everything is stderr.

**Share rate limiting was on this list and is not any more**: it is in, because
a public solo offering is untrusted workers and there is no cheap pre-filter
for Avian's proof of work. See [Solo mining](#submission-rate-limiting).

### Smaller gaps

- A channel is only unregistered when its reader loop ends, so a job pushed to
  a socket that has just gone away logs a broken pipe first. It self-heals on
  the next read; the log line is noise rather than a leak.
- Backoff has no jitter. Fine for one miner on loopback, wrong for a pool with
  many miners reconnecting together.
