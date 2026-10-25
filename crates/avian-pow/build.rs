//! Compiles Avian's own X16RT and MinotaurX sources into a static library.
//!
//! The source list is the one `src/CMakeLists.txt` uses for `algo/`, plus
//! `uint256.cpp`, which is all the two inline templates need. Nothing is
//! copied into this repository and nothing in the Avian tree is written to.
//!
//! `AVIAN_SRC` points at the Avian Core `src` directory. Without it the build
//! emits `cargo:rustc-cfg=no_avian_pow` and the crate compiles to a stub that
//! reports itself unavailable, so `cargo build` works on a machine without the
//! Avian tree.

use std::path::{Path, PathBuf};

// algo/x16r/sph_sha2.c and sha2.c are both listed by CMakeLists and are not
// duplicates: one is the sph API, the other the x16r-local one.
const X16R_SOURCES: &[&str] = &[
    "blake.c",
    "bmw.c",
    "cubehash.c",
    "echo.c",
    "fugue.c",
    "gost_streebog.c",
    "groestl.c",
    "hamsi.c",
    "haval.c",
    "jh.c",
    "keccak.c",
    "luffa.c",
    "sha2.c",
    "shabal.c",
    "shavite.c",
    "simd.c",
    "skein.c",
    "sph_sha2.c",
    "sph_sha2big.c",
    "whirlpool.c",
];

const X16R_CXX_SOURCES: &[&str] = &["lyra2.cpp", "sponge.cpp", "tiger.cpp"];

const MINOTAURX_C_SOURCES: &[&str] = &["blake2s-ref.c"];
const MINOTAURX_CXX_SOURCES: &[&str] = &["pbkdf2.cpp"];
const YESPOWER_SOURCES: &[&str] = &["yespower.c", "crypto/sha256.c"];

fn main() {
    println!("cargo:rustc-check-cfg=cfg(no_avian_pow)");
    println!("cargo:rerun-if-env-changed=AVIAN_SRC");

    let Some(src) = avian_src() else {
        println!("cargo:rustc-cfg=no_avian_pow");
        println!(
            "cargo:warning=avian-pow: no Avian source tree found. Set AVIAN_SRC to \
             <avian>/src to build the real hashers; share validation will refuse to run \
             without it."
        );
        return;
    };
    println!("cargo:rerun-if-changed=csrc/shim.cpp");

    let x16r = src.join("algo/x16r");
    let minotaurx = src.join("algo/minotaurx");
    let yespower = minotaurx.join("yespower");

    // The sph_* sources are warning-noisy third-party code and some of them
    // rely on type punning, so strict aliasing is off for the whole library.
    let mut c = cc::Build::new();
    c.include(&src)
        .include(&x16r)
        .include(&minotaurx)
        .include(&yespower)
        .flag_if_supported("-fno-strict-aliasing")
        .flag_if_supported("-w")
        .warnings(false);
    for file in X16R_SOURCES {
        c.file(x16r.join(file));
    }
    for file in MINOTAURX_C_SOURCES {
        c.file(minotaurx.join(file));
    }
    for file in YESPOWER_SOURCES {
        c.file(yespower.join(file));
    }
    c.compile("avian_algo_c");

    let mut cxx = cc::Build::new();
    cxx.cpp(true)
        .std("c++20")
        .include(&src)
        .include(&x16r)
        .include(&minotaurx)
        .include(&yespower)
        .flag_if_supported("-fno-strict-aliasing")
        .flag_if_supported("-w")
        .warnings(false);
    for file in X16R_CXX_SOURCES {
        cxx.file(x16r.join(file));
    }
    for file in MINOTAURX_CXX_SOURCES {
        cxx.file(minotaurx.join(file));
    }
    cxx.file(src.join("uint256.cpp"));
    cxx.file("csrc/shim.cpp");
    cxx.compile("avian_algo_cxx");
}

fn avian_src() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("AVIAN_SRC") {
        let path = PathBuf::from(path);
        return usable(&path).then_some(path);
    }
    // The sibling checkout, which is where it sits in this workspace.
    let guess = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../Avian-v5.0/src")
        .canonicalize()
        .ok()?;
    usable(&guess).then_some(guess)
}

fn usable(src: &Path) -> bool {
    src.join("algo/x16r/x16r.h").exists()
        && src.join("algo/minotaurx/minotaurx.h").exists()
        && src.join("uint256.cpp").exists()
}
