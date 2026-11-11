# avian-sv2

Stratum v2 for [Avian](https://avn.network), without ever holding anyone's
coins: **`libavian-sv2`**, the protocol library with a C API that pools and
miners are built on, and **`avian-sv2-solo`**, a Stratum v2 solo mining pool
built on it.

Non-custodial is the line this project holds, and solo is how it holds it
today. A solo pool has nothing to hold: the miner puts its own payout address
in `user_identity` when it opens a channel, the coinbase pays that address,
and consensus pays the miner directly. A miner that would rather not have every
block land on one address gives a descriptor instead, `wpkh(xpub.../0/*)`, and
each block pays the next address under it. Pooled mining means holding other
people's money between a block and a payout, which is the part that is not
here and the reason there is no `avian-sv2-pool`. An operator who already runs
a pool and wants Stratum v2 at the miner edge does not need one either: see
[in front of a pool that already exists](#in-front-of-a-pool-that-already-exists).

The library carries the protocol core and the Mining Protocol client, so a C
or CUDA miner links a static library and a header instead of writing Stratum
v2, Noise included, a second and third time. The solo pool consumes the same
library as an ordinary Rust crate and adds the two halves a miner never needs:
the Template Distribution client it is to the node, and the Mining Protocol
server it is to workers.

```
crates/avian-sv2        libavian-sv2: Noise, framing, extension codecs,
                        the Mining Protocol client, and the C API
crates/avian-pow        Avian's X16RT and MinotaurX. NOT in the library
crates/avian-tdp        the pool's Template Distribution client and coinbase
crates/avian-mining     the pool's Mining Protocol server and wiring
crates/avian-sv1        a Stratum v1 client, for the bridge's upstream
crates/avian-sv2-solo   the solo pool binary
crates/avian-sv2-bridge a Stratum v2 front for an existing Stratum v1 pool
crates/avian-regtest    starts a regtest node for tests; test support only
```

## Status

Working, on regtest, for both of Avian's proof of work algorithms, over both
standard and extended channels, driven from Rust and from a C program that
links the static library. Blocks are found by hashing, relayed by the pool,
accepted by the node, reported by `getblock` under the algorithm that was
negotiated, and pay the address the miner supplied at channel open.

That last part is checked explicitly against the node's own view of the block,
because it is the only part of solo mining that cannot be inferred from the
protocol working: every protocol assertion would pass just as happily if the
coinbase paid the operator.

Not yet run against mainnet or by anyone other than its author.

## Building

```sh
cargo build --release
```

Rust 1.75 or later. The dependencies are the Stratum v2 Reference
Implementation's codec crates, plus `secp256k1` and `cc`, both already in the
tree at the versions SRI pins.

**The library alone needs no C++ toolchain and no Avian source tree:**

```sh
cargo build --release -p avian-sv2
```

The pool does, because it checks shares and therefore links Avian's own
hashers. `crates/avian-pow/build.rs` looks for the Avian `src` directory
beside this repository, or at `AVIAN_SRC`. Without one everything still
compiles, but the hashers report themselves unavailable and the pool refuses
to start rather than accepting every share:

```sh
AVIAN_SRC=/path/to/avian/src cargo build --release
```

On Windows the hashers build with mingw and not with MSVC: Avian's
`yespower.c` carries a `#warning`, which `cl.exe` rejects outright. With
MSYS2's `mingw64/bin` on `PATH`:

```sh
cargo build --release --target x86_64-pc-windows-gnu
```

The MSVC target still builds everything that does not hash: the library, the
bridge, and `avian-mining` without its `pow` feature.

`avian-mining` links them through its `pow` feature, which is on by default.
A consumer that never validates a share itself can turn it off and build
with no C++ toolchain at all:

```sh
cargo build --release -p avian-mining --no-default-features
```

## Running the solo pool

Start a regtest node with Stratum v2 enabled, and **generate a block first**:
the node refuses to build templates while it considers itself in initial block
download, and refuses silently.

```sh
aviand -regtest -datadir=/tmp/sv2 -sv2 \
       -sv2powalgo=x16rt -sv2powalgo=minotaurx -daemon
avian-cli -regtest -datadir=/tmp/sv2 createwallet w
ADDR=$(avian-cli -regtest -datadir=/tmp/sv2 getnewaddress)
avian-cli -regtest -datadir=/tmp/sv2 generatetoaddress 101 $ADDR

cargo run --release -p avian-sv2-solo -- --datadir /tmp/sv2
```

The node listens on `127.0.0.1:18447` by default; the pool opens one Template
Distribution connection per algorithm and serves the Mining Protocol on
`127.0.0.1:34254`. `--coinbase-tag`, `--operator-fee` and `--operator-fee-bp`
are the options an operator is likely to want. The pool generates an authority
key on first run and prints where it put it; miners pin that key.

## In front of a pool that already exists

An operator running a Stratum v1 pool today needs none of the above to offer
Stratum v2. What they are missing is the protocol edge, not accounting, and
`avian-sv2-bridge` is that edge: it terminates Stratum v2 and Noise downstream
and speaks Stratum v1 upstream to the pool they already run, one upstream
connection per miner, opened in the name the miner put in `user_identity`.
Their miners get encryption, an authenticated pool identity, binary framing and
a coinbase they can read; their own stratum server goes on crediting shares and
paying them, untouched. The bridge holds nothing and credits nothing, which is
why it belongs here.

```sh
cargo run --release -p avian-sv2-bridge -- \
    --upstream x16rt=pool.example:3333 --upstream minotaurx=pool.example:3334
```

Miners connect to it exactly as they would to the solo pool, pinning the
authority key it prints. It builds with no Avian source tree and no C++
toolchain, because the pool judges every share's hash; `--features pow` adds
the hashers, so a share under the target is refused before it costs the pool a
round trip. The one Stratum v2 benefit it cannot deliver is job declaration:
the pool chooses the block.
[`doc/design.md`](doc/design.md#in-front-of-a-pool-that-already-exists) has
the message mapping, the difficulty conversion and the reasons.

## Using the library from C

```sh
cargo build --release -p avian-sv2
cc -I crates/avian-sv2/include my_miner.c \
   target/release/libavian_sv2.a -lpthread -ldl -lm -o my_miner
```

The static library carries the whole Rust standard library, so nothing beyond
libc, libm, libdl and libpthread is needed. The header,
`crates/avian-sv2/include/avian_sv2.h`, is hand written and kept honest by a C
program compiled against it with `-Werror` in the tests. The boundary is the
neutral `AvianMiningJob`: the C side sees jobs and submits shares, and never
sees Noise, framing or a Stratum v2 type.

[avian-miner](https://github.com/cdonnachie/avian-miner) is the real consumer
of that API.

## Tests

```sh
cargo test
```

198 tests. Those that need one start a real regtest `aviand` and skip with a
message when it is not found; `AVIAND` and `AVIAN_CLI` override the default of
`~/avian-build/bin`. `crates/avian-mining/tests/c_api.rs` compiles and runs a C
program against the header with `-Werror`, and `CC` overrides `cc`. On Windows
add `--target x86_64-pc-windows-gnu`, for the reason given under building.

## Documentation

[`doc/design.md`](doc/design.md) is the long version: why solo mining shapes
the identity format the way it does, what the Stratum v2 specification leaves
undefined and what this does about it, the two interoperability defects found
while building it and how they were fixed, the reconnection semantics, how the
bridge in front of an existing pool works, and what is deliberately not here.

## Licence

MIT, see [LICENSE](LICENSE). Note that avian-miner, which links this library,
is GPL-3; MIT is compatible with that, and the combined binary is distributed
under the GPL.
