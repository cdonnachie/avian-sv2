# avian-sv2

Stage 2 of the Avian Stratum v2 pool: a Rust Template Distribution Protocol
client that connects to a live `aviand`, negotiates Avian's `0x4001`
extension, and receives block templates for both of Avian's proof-of-work
algorithms.

No Mining Protocol, no mining channels, no share accounting, no payouts. Those
are Stage 3 and later. See `Avian-Native-Stratum-V2-Mining-Plan.md` section 25.

```
crates/avian-tdp        the library: Noise, framing, codecs, session
crates/avian-sv2-pool   the binary: one session per algorithm
```

## The two findings that shaped this

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

Needs Rust 1.75 or later. Dependencies are SRI's `codec_sv2`, `noise_sv2`,
`framing_sv2`, `binary_sv2`, `common_messages_sv2` and
`template_distribution_sv2`, plus `secp256k1` at the version `noise_sv2`
already pins — needed only to turn the node's authority private key file into
the x-only public key `noise_sv2` checks the certificate against. Nothing
else.

## Running it against a node

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

That opens one connection per algorithm and prints every round of work until
killed. `--duration <seconds>` stops on its own.

The certificate is verified against the authority key by default, derived from
the 32 raw bytes the node writes to `<datadir>/regtest/sv2_authority_key` on
first run. `--authority <hex>` takes the x-only public key directly, for an
operator who does not have the node's datadir. `--insecure-tofu` skips the
check; the session is still encrypted, but nothing says the peer is the node
you meant.

The client connects to loopback only, and refuses anything else.

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

`crates/avian-sv2-pool/tests/live_node.rs` starts a regtest `aviand`, mines
101 blocks, opens a session per algorithm and asserts that a template arrived
for each with the right algorithm in `version` bits 16-23, that
`AvianTimeConstraints` keys to the same template and agrees with
`SetNewPrevHash`, that `RequestTransactionData` answers, and that an unknown
template id is refused rather than disconnected. A second test asserts a tip
change pushes fresh work.

Both skip with a message when `aviand` is not found. `AVIAND` and `AVIAN_CLI`
override the default of `~/avian-build/bin`.

The nodes the tests start pass `-listen=0`. Without it they bind the regtest
P2P port and refuse to start if a node is already running by hand.

## Where doc/sv2.md falls short

This matters because that document is about to be used for a registry
allocation and third-party implementers will build against it.

**1. The Noise handshake, above. Fixed in the node; the claim is now true.**
It was the costliest thing in the document, because it was the one claim an
implementer would not think to test: reach for SRI, get a MAC failure with no
diagnostic, and have no reason to suspect the handshake rather than your own
code. Kept here as the record of why this client was worth writing.

**2. `SetNewPrevHash` is documented as conditional and is not.** The document
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

**3. `SetNewPrevHash`'s third field is named twice.** The document, and
`mining_sv2.py`, call it `ntime_start`:

> the `AvianTimeConstraints` `ntime_min` equals the `ntime_start` in the
> `SetNewPrevHash` for that template

The Stratum v2 spec and SRI's `template_distribution_sv2::SetNewPrevHash` call
that field `header_timestamp`; `ntime_start` and `min_ntime` are Mining
Protocol names. An implementer using SRI's structs has to work out that the two
are the same field. Worth one parenthesis in the document, since it never
tabulates the stock messages.

**4. Three error codes the node sends are not in the document, and one that is
disagrees with SRI.** The codes the document names are
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

**5. A malformed extension message is a disconnect, not an error reply.** The
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
pool will actually build.** The document says the node will not issue a
template before it arrives and that "the coinbase size and sigop budget it
declares are what the block assembler reserves". What it does not say is what
happens if a pool under-declares: the coinbase it then builds fails the
canonical re-serialization check and the submission is refused with nothing on
the wire. One sentence saying the declared size must cover every output the
pool adds, not just its payout, would save an implementer a silent failure.

## Design, and the seam for Stage 3

```
avian-tdp::transport   SRI's Noise and framing, over a blocking socket
avian-tdp::avian       extension 0x4001 and negotiation extension 0x0001
avian-tdp::tdp         the stock Template Distribution messages, owned
avian-tdp::session     one connection, one algorithm
avian-sv2-pool         one AlgoContext per algorithm
```

Three things are kept separable because Stage 3 needs them apart:

- **The TDP session knows nothing about mining.** `TdpSession` produces rounds
  of work for one algorithm. A Mining Protocol server owns one per algorithm
  and never has to reach inside it.
- **The Avian extension codecs are not Template Distribution specific.**
  `avian::encode_job_time_constraints` and `decode_job_time_constraints` are
  there now, unused, because `AvianJobTimeConstraints` is the Mining Protocol
  half of the same extension and travels under `0xc001`. The transport already
  sets and reads the `channel_msg` bit.
- **Per-algorithm state lives in `AlgoContext`.** Avian's two algorithms have
  independent difficulty, independent targets and independent job streams, so
  nothing is shared between them. One connection carries one algorithm, which
  is why a pool mining both opens two.

## What is not here

- The Mining Protocol, mining channels, `SetTarget`, jobs, shares, payouts.
- `SubmitSolution`. The client never builds a coinbase, so there is nothing to
  submit. The coinbase contract in doc/sv2.md is the pool's to satisfy, and it
  belongs with the code that builds one.
- Reconnection. A session that fails reports and stops.
- Anything non-loopback.
