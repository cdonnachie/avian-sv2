//! Compiles a C program against the static libraries and runs it.
//!
//! Not a Rust test calling the `extern "C"` functions: that would be the API
//! talking to itself. This invokes a C compiler on `ctest/session.c`, links
//! `libavian_sv2.a` and `libavian_pow.a`, and runs the result against a live
//! pool backed by a live node. If the C program cannot be made to work, this
//! test is where it shows.
//!
//! It also pins the two things that silently rot: the hand-written header
//! going out of step with `capi.rs`, which stops the program compiling, and
//! the link line in the header's own comment going out of step with what
//! actually links, which stops it linking.

// These tests hash, so they need the hashers the `pow` feature links.
#![cfg(feature = "pow")]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use avian_sv2::avian::PowType;
use common::Rig;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/avian-mining.
    plain(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root"),
    )
}

/// Takes Windows' `\\?\` verbatim prefix back off a canonicalized path.
///
/// `canonicalize` always adds it and a mingw `cc` reads it as a share named
/// `?`, so every path handed to the C compiler goes through here. A no-op
/// everywhere else.
fn plain(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

/// The triple this test was compiled for, put together from the pieces the
/// compiler does expose, because it does not expose the triple itself.
fn own_triple() -> String {
    let vendor = if cfg!(target_vendor = "apple") {
        "apple"
    } else if cfg!(target_vendor = "pc") {
        "pc"
    } else {
        "unknown"
    };
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        std::env::consts::OS
    };
    let env = if cfg!(target_env = "gnu") {
        "-gnu"
    } else if cfg!(target_env = "msvc") {
        "-msvc"
    } else if cfg!(target_env = "musl") {
        "-musl"
    } else {
        ""
    };
    format!("{}-{vendor}-{os}{env}", std::env::consts::ARCH)
}

fn cc() -> String {
    std::env::var("CC").unwrap_or_else(|_| "cc".to_string())
}

/// Builds the two static libraries and compiles the C program against them.
///
/// Returns `None` when there is no C compiler, so the suite still passes on a
/// machine without one, and says so rather than skipping quietly.
fn build_c_program(root: &Path) -> Option<PathBuf> {
    if Command::new(cc()).arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler; set CC to override");
        return None;
    }

    // The same cargo profile and target this test is running under, so the
    // test does not build a second copy of the world. Both are read off this
    // binary's own path, <target>/[<triple>/]<profile>/deps/<exe>, because a
    // test built with `--target` is told nothing else about it: cargo names
    // the directory for the triple and keeps the triple to itself.
    let exe = std::env::current_exe().expect("the test binary's own path");
    let profile_dir = plain(
        exe.parent()
            .and_then(Path::parent)
            .expect("the profile directory")
            .to_path_buf(),
    );
    let profile = profile_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the profile name")
        .to_string();
    let triple = own_triple();
    let cross = profile_dir
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        == Some(triple.as_str());
    for package in ["avian-sv2", "avian-pow"] {
        let mut build = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        build.current_dir(root).args(["build", "-p", package]);
        match profile.as_str() {
            "debug" => {}
            "release" => {
                build.arg("--release");
            }
            custom => {
                build.args(["--profile", custom]);
            }
        }
        if cross {
            build.args(["--target", &triple]);
        }
        let output = build.output().expect("cargo build");
        assert!(
            output.status.success(),
            "building {package} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let sv2 = profile_dir.join("libavian_sv2.a");
    let pow = profile_dir.join("libavian_pow.a");
    assert!(sv2.exists(), "{} was not produced", sv2.display());
    assert!(pow.exists(), "{} was not produced", pow.display());

    // libstdc++ because Avian's lyra2, sponge, tiger and uint256 are C++; the
    // rest is what the Rust standard library needs, which is what
    // `cargo rustc -- --print native-static-libs` lists for the target. On
    // Windows that means mingw, and `-static` keeps mingw's own runtime DLLs
    // from being needed beside the program.
    let system: &[&str] = if cfg!(windows) {
        &[
            "-static",
            "-lstdc++",
            "-lpthread",
            "-lbcrypt",
            "-ladvapi32",
            "-lkernel32",
            "-lntdll",
            "-luserenv",
            "-lws2_32",
            "-ldbghelp",
            "-lm",
        ]
    } else {
        &["-lstdc++", "-lpthread", "-ldl", "-lm"]
    };

    let out = std::env::temp_dir().join(format!(
        "avian-c-session-{}{}",
        std::process::id(),
        std::env::consts::EXE_SUFFIX
    ));
    let status = Command::new(cc())
        .current_dir(root)
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            "crates/avian-sv2/include",
            "-I",
            "crates/avian-pow/include",
            "crates/avian-sv2/ctest/session.c",
        ])
        .arg(&sv2)
        .arg(&pow)
        .args(system)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("cc");
    assert!(
        status.success(),
        "the C program did not compile or link. This is the finding: the header, the link line \
         in its comment, or the API itself is wrong."
    );
    Some(out)
}

#[test]
fn a_c_program_mines_a_share_through_the_static_library() {
    let root = workspace_root();
    let Some(program) = build_c_program(&root) else {
        return;
    };

    let rig = match Rig::start("capi", 30, &[PowType::X16rt, PowType::MinotaurX], None) {
        Some(rig) => rig,
        None => {
            eprintln!("skipping: aviand or avian-cli not found");
            return;
        }
    };

    // In the form a miner's configuration takes, which is what the C program
    // would be given by an operator.
    let authority = avian_sv2::address::encode_authority_key(&rig.pool_authority);
    // Both kinds of channel, because serving both is the point and a C miner
    // is the only thing that proves the extended path is usable from C.
    for (algorithm, extended) in [("x16rt", true), ("minotaurx", true), ("x16rt", false)] {
        rig.wait_for_tip(match algorithm {
            "x16rt" => PowType::X16rt,
            _ => PowType::MinotaurX,
        });
        let before = rig.node.height();
        let output = Command::new(&program)
            .arg(rig.pool.mining_addr().to_string())
            .arg(&authority)
            .arg(algorithm)
            .arg(common::WORKER_ADDRESS)
            .env("AVIAN_SV2_EXTENDED", if extended { "1" } else { "0" })
            .output()
            .expect("running the C program");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("--- C program, {algorithm} ---\n{stdout}{stderr}");
        assert!(
            output.status.success(),
            "the C program failed for {algorithm}:\n{stdout}{stderr}\nNode's sv2 log:\n{}",
            rig.node.sv2_log()
        );

        assert!(
            stdout.contains("connected and opened"),
            "the C program did not get a channel:\n{stdout}"
        );
        if extended {
            assert!(
                stdout.contains("an extended channel"),
                "the C program should have opened an extended channel:\n{stdout}"
            );
            // What extended channels are for, from C: it read the coinbase it
            // was committing to rather than trusting a merkle root.
            assert!(
                stdout.contains("coinbase I assembled"),
                "the C program should have read its own coinbase:\n{stdout}"
            );
        } else {
            assert!(
                stdout.contains("a standard channel"),
                "the C program should have opened a standard channel:\n{stdout}"
            );
        }
        assert!(
            stdout.contains("share") && stdout.contains("accepted"),
            "the C program did not have a share accepted:\n{stdout}"
        );
        assert!(
            stdout.contains("reconnected as generation"),
            "the C program did not reconnect:\n{stdout}"
        );

        // On regtest the share target is the network target, so an accepted
        // share is also a block: the pool forwarded it to the node and the
        // node took it. That is the whole chain, driven from C.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while rig.node.height() == before && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            rig.node.height(),
            before + 1,
            "the node should have accepted the block the C program found:\n{stdout}"
        );
        assert_eq!(
            rig.node.pow_type_of(&rig.node.tip()).as_deref(),
            Some(algorithm),
            "getblock should report the algorithm the C program negotiated"
        );
        // And the money went where the C program asked, which is the only
        // part of solo mining the protocol working does not prove.
        let block = rig
            .node
            .rpc(&["getblock", &rig.node.tip(), "2"])
            .expect("getblock");
        assert!(
            block.contains(common::WORKER_SCRIPT),
            "the coinbase of the block the C program mined must pay {}",
            common::WORKER_ADDRESS
        );
        eprintln!(
            "[test] a C program mined {algorithm} block {} at height {} over {} channel",
            rig.node.tip(),
            rig.node.height(),
            if extended {
                "an extended"
            } else {
                "a standard"
            }
        );
    }

    let _ = std::fs::remove_file(&program);
}
