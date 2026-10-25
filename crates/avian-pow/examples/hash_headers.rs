//! Prints Avian's MinotaurX hash for each 80-byte header given as hex.
//!
//! This exists so a candidate miner's MinotaurX can be compared with Avian's
//! without both implementations in one process. Both vendor yespower and
//! export the same symbol names, so a single binary containing both resolves
//! one side's call into the other and agreement proves nothing.

use avian_pow::{hash, PowType, AVAILABLE};

fn main() {
    if !AVAILABLE {
        eprintln!("avian-pow was built without Avian's sources");
        std::process::exit(2);
    }
    let mut args = std::env::args().skip(1).peekable();
    let pow = match args.peek().map(String::as_str) {
        Some("x16rt") => {
            args.next();
            PowType::X16rt
        }
        Some("minotaurx") => {
            args.next();
            PowType::MinotaurX
        }
        _ => PowType::MinotaurX,
    };
    for arg in args {
        let bytes = match decode_hex(&arg) {
            Some(bytes) if bytes.len() == 80 => bytes,
            _ => {
                eprintln!("not 80 bytes of hex: {arg}");
                std::process::exit(2);
            }
        };
        let header: [u8; 80] = bytes.try_into().expect("checked above");
        let Some(digest) = hash(pow, &header) else {
            eprintln!("avian-pow could not hash the header");
            std::process::exit(2);
        };
        let mut out = String::with_capacity(64);
        for byte in digest {
            out.push_str(&format!("{byte:02x}"));
        }
        println!("{out}");
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
        .collect()
}
