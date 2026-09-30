/// Calculates Shannon Entropy for a byte slice (0.0 to 8.0)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Detects well-known cryptographic lookup tables and constants
pub fn detect_crypto_constants(data: &[u8]) -> Vec<String> {
    let mut found = Vec::new();

    // AES S-Box start sequence: 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    const AES_SBOX: [u8; 16] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ];
    if contains_subslice(data, &AES_SBOX) {
        found.push("AES (Rijndael S-Box)".to_string());
    }

    // SHA-256 initial constants: 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a (in little-endian bytes)
    const SHA256_INIT: [u8; 16] = [
        0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
    ];
    if contains_subslice(data, &SHA256_INIT) {
        found.push("SHA-256 (Hash Constants)".to_string());
    }

    // SHA-1 initial constants: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    const SHA1_INIT: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    if contains_subslice(data, &SHA1_INIT) {
        found.push("SHA-1 (Hash Constants)".to_string());
    }

    // MD5 initial constants: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    // Same as SHA-1 in parts, check for MD5 transform sin constants
    const MD5_CONST: [u8; 8] = [0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8];
    if contains_subslice(data, &MD5_CONST) {
        found.push("MD5 (Transform Table)".to_string());
    }

    // ChaCha20 / Salsa20 constant "expand 32-byte k"
    const CHACHA_CONST: &[u8] = b"expand 32-byte k";
    if contains_subslice(data, CHACHA_CONST) {
        found.push("ChaCha20 / Poly1305".to_string());
    }

    // CRC32 IEEE 802.3 lookup table start (0x00000000, 0x77073096, 0xee0e612c, 0x990951ba)
    const CRC32_TABLE: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee, 0xba, 0x51, 0x09, 0x99,
    ];
    if contains_subslice(data, &CRC32_TABLE) {
        found.push("CRC-32 (IEEE Table)".to_string());
    }

    found
}

fn contains_subslice(data: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || data.len() < pattern.len() {
        return false;
    }
    data.windows(pattern.len()).any(|window| window == pattern)
}
