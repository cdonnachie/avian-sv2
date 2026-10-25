//! Avian's proof-of-work hashes, from Avian's own implementation.
//!
//! A pool has to compare a submitted share against a target, and for Avian
//! that target is compared against the X16RT or MinotaurX hash, not SHA256d.
//! Reimplementing either in Rust would be its own project with its own test
//! vectors, and a reimplementation that is subtly wrong is worse than no
//! implementation at all, so this links Avian's C and C++ sources directly.
//! See `build.rs` for the source list and how it is located.

#[cfg(not(no_avian_pow))]
mod ffi {
    extern "C" {
        pub fn avian_x16rt_seed(ntime: u32, out32: *mut u8);
        pub fn avian_x16rt_hash(
            header: *const u8,
            header_len: std::ffi::c_ulong,
            seed32: *const u8,
            out32: *mut u8,
        );
        pub fn avian_minotaurx_hash(
            header: *const u8,
            header_len: std::ffi::c_ulong,
            out32: *mut u8,
        );
    }
}

/// Whether the real hashers were compiled in.
pub const AVAILABLE: bool = cfg!(not(no_avian_pow));

/// X16RT rederives its hash chain every 128 seconds, from
/// `SHA256d(nTime & 0xffffff80)`.
pub const TIME_MASK: u32 = 0xffff_ff80;

/// `SHA256d(nTime & TIME_MASK)`, the seed that selects X16RT's hash order.
///
/// Returns `None` when the crate was built without the Avian sources.
pub fn x16rt_seed(ntime: u32) -> Option<[u8; 32]> {
    #[cfg(no_avian_pow)]
    {
        let _ = ntime;
        None
    }
    #[cfg(not(no_avian_pow))]
    {
        let mut out = [0u8; 32];
        // Safety: the shim writes exactly 32 bytes and reads nothing else.
        unsafe { ffi::avian_x16rt_seed(ntime, out.as_mut_ptr()) };
        Some(out)
    }
}

/// The X16RT hash of a serialized header, given the seed from [`x16rt_seed`].
///
/// [`hash`] is the usual entry point; this one exists so a caller that
/// already has the seed does not recompute it per nonce.
///
/// Returns `None` when the crate was built without the Avian sources.
pub fn x16rt(header: &[u8], seed: &[u8; 32]) -> Option<[u8; 32]> {
    #[cfg(no_avian_pow)]
    {
        let _ = (header, seed);
        None
    }
    #[cfg(not(no_avian_pow))]
    {
        let mut out = [0u8; 32];
        // Safety: both pointers are to live slices of the lengths given, and
        // the shim only reads `header_len` bytes and writes exactly 32.
        unsafe {
            ffi::avian_x16rt_hash(
                header.as_ptr(),
                header.len() as std::ffi::c_ulong,
                seed.as_ptr(),
                out.as_mut_ptr(),
            );
        }
        Some(out)
    }
}

/// The MinotaurX hash of a serialized header.
///
/// Returns `None` when the crate was built without the Avian sources.
pub fn minotaurx(header: &[u8]) -> Option<[u8; 32]> {
    #[cfg(no_avian_pow)]
    {
        let _ = header;
        None
    }
    #[cfg(not(no_avian_pow))]
    {
        let mut out = [0u8; 32];
        // Safety: as above.
        unsafe {
            ffi::avian_minotaurx_hash(
                header.as_ptr(),
                header.len() as std::ffi::c_ulong,
                out.as_mut_ptr(),
            );
        }
        Some(out)
    }
}

/// 0 = X16RT, 1 = MinotaurX, matching `POW_TYPE` and the extension's
/// `pow_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowType {
    X16rt = 0,
    MinotaurX = 1,
}

/// The proof-of-work hash of an 80-byte header, for either algorithm.
///
/// The bytes are in the same order `CBlockHeader::GetHash` produces, which is
/// the reverse of how a block hash is displayed.
pub fn hash(pow: PowType, header: &[u8]) -> Option<[u8; 32]> {
    match pow {
        PowType::X16rt => {
            // nTime is the header's 69th through 72nd bytes.
            let ntime = u32::from_le_bytes(header.get(68..72)?.try_into().ok()?);
            x16rt(header, &x16rt_seed(ntime)?)
        }
        PowType::MinotaurX => minotaurx(header),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Headers and hashes of real regtest blocks, taken from
    // `getblock <hash> 0` and `getblockhash`, with the algorithm each was
    // mined under from `getblock`'s powtype. These are the node's own output,
    // so they are ground truth for what the pool has to reproduce.
    const VECTORS: &[(PowType, &str, &str)] = &[
        (
            PowType::X16rt,
            "000000227f78cf1d89b20dbe77361d6a87e47bad06399047dda5abe884ed273dd034\
             36655711eea98921899ddac2f0973fb14fcac050319d996f64cdfa633710945f5b85\
             7c31de6affff7f2001000000",
            "149c3bc973245ac72f30b12ab3bed634241193c4a4894f4b4aa8b348cd9430c2",
        ),
        (
            PowType::X16rt,
            "00000032c23094cd48b3a84a4b4f89a4c493112434d6beb32ab1302fc75a2473c93b\
             9c144679af9dfad912fda715d0256d9ae5d61f2be4ecd2135c92319bf6cd464b93e6\
             7d31de6affff7f2001000000",
            "6606b09d63161ea417c086c6e46a892869b4e5359c7cea9a8048532b39129b77",
        ),
        (
            PowType::MinotaurX,
            "00000132779b12392b5348809aea7c9c35e5b46928896ae4c686c017a41e16639db0\
             06660da3727a04ccf5adfde3ae4cac4770f54e0a37cc482f6699f7dee442f8c68ab3\
             7d31de6affff7f2000000000",
            "23fdef520e8b633bf7c3981fbec06add17090f7be185a70c261dd0ba85a63dcc",
        ),
        (
            PowType::MinotaurX,
            "00000132cc3da685bad01d260ca785e17b0f0917dd6ac0be1f98c3f73b638b0e52ef\
             fd235e18e85e588e466a3689d4f3b675f00dac4998ed309bc84cfd55038775bd04e7\
             7e31de6affff7f2000000000",
            "7a929b764d70ce29445579dec85ec5b7176ec6a0139a006f1bf38fc30f62e9be",
        ),
    ];

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn matches_real_regtest_blocks() {
        if !AVAILABLE {
            eprintln!("skipping: built without the Avian sources");
            return;
        }
        for (pow, header, expected) in VECTORS {
            let header = unhex(header);
            assert_eq!(header.len(), 80, "a header is 80 bytes");
            let got = hash(*pow, &header).expect("hasher");
            // A block hash is displayed reversed.
            let mut shown = got;
            shown.reverse();
            assert_eq!(
                shown.to_vec(),
                unhex(expected),
                "{pow:?} hash of {}",
                expected
            );
        }
    }

    #[test]
    fn the_two_algorithms_disagree() {
        if !AVAILABLE {
            return;
        }
        let header = unhex(VECTORS[0].1);
        assert_ne!(
            hash(PowType::X16rt, &header).unwrap(),
            hash(PowType::MinotaurX, &header).unwrap(),
            "the same header must hash differently under each algorithm, or the \
             pow_type argument is being ignored"
        );
    }

    #[test]
    fn the_seed_follows_the_128_second_epoch() {
        if !AVAILABLE {
            return;
        }
        // Everything inside one epoch shares a seed; the next second over the
        // boundary does not. This is the property an X16RT ntime window has to
        // respect.
        let base = 1_792_943_722u32 & TIME_MASK;
        assert_eq!(x16rt_seed(base), x16rt_seed(base + 127));
        assert_ne!(x16rt_seed(base), x16rt_seed(base + 128));
    }
}
