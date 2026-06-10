//! OSC 52 clipboard copy — the terminal escape sequence that asks the
//! hosting terminal emulator to place text on the system clipboard.
//!
//! The sequence travels the tty back to the operator's terminal, so it
//! works **through SSH**: the consent URL lands on the clipboard of the
//! machine the operator is physically at — exactly the handoff the
//! OAuth consent blocks need. Terminals without OSC 52 support ignore
//! the sequence; emission is fire-and-forget.
//!
//! Hand-rolled RFC 4648 base64 (≈20 lines) instead of a `base64` crate
//! dependency: the only consumer is this escape-sequence payload.

use std::io::Write;

/// Emit an OSC 52 copy-to-clipboard sequence for `text` on stderr.
pub fn emit_osc52_copy(text: &str) {
    let payload = encode_base64_standard(text.as_bytes());
    eprint!("\x1b]52;c;{payload}\x07");
    let _ = std::io::stderr().flush();
}

fn encode_base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHABET[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() >= 3 {
            out.push(ALPHABET[(b2 & 0b111111) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::encode_base64_standard;

    /// RFC 4648 §10 test vectors.
    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode_base64_standard(b""), "");
        assert_eq!(encode_base64_standard(b"f"), "Zg==");
        assert_eq!(encode_base64_standard(b"fo"), "Zm8=");
        assert_eq!(encode_base64_standard(b"foo"), "Zm9v");
        assert_eq!(encode_base64_standard(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64_standard(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64_standard(b"foobar"), "Zm9vYmFy");
    }
}
