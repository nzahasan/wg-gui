//! Minimal base64 decoder. WireGuard keys are 32 bytes encoded as 44
//! base64 characters (43 data characters plus one `=` pad).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value_of(c: u8) -> Result<u32, String> {
    match ALPHABET.iter().position(|&a| a == c) {
        Some(v) => Ok(v as u32),
        None => Err(format!("invalid base64 character '{}'", c as char)),
    }
}

/// Decodes standard base64 (with `=` padding) into bytes.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.trim().as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length must be a multiple of 4".to_string());
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        // Count the trailing '=' characters; they tell us how many of the
        // three output bytes are real.
        let padding = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if padding > 2 {
            return Err("too much base64 padding".to_string());
        }

        let mut bits: u32 = 0;
        for &c in chunk {
            let v = if c == b'=' { 0 } else { value_of(c)? };
            bits = (bits << 6) | v;
        }

        let decoded = [(bits >> 16) as u8, (bits >> 8) as u8, bits as u8];
        out.extend_from_slice(&decoded[..3 - padding]);
    }
    Ok(out)
}

/// Decodes a base64 string that must produce exactly 32 bytes (a key).
pub fn decode_key(text: &str) -> Result<[u8; 32], String> {
    let bytes = decode(text)?;
    bytes
        .try_into()
        .map_err(|_| "key must decode to exactly 32 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_strings() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn decodes_a_wireguard_key() {
        // 32 bytes of 0x00..0x1f.
        let key = decode_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap();
        let expected: Vec<u8> = (0..32).collect();
        assert_eq!(key.to_vec(), expected);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("Zm9").is_err());
        assert!(decode("Zm9!").is_err());
        assert!(decode_key("Zm9v").is_err());
    }
}
