use sha2::{Digest, Sha256};

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_is_deterministic() {
        assert_eq!(sha256(b"upgraderail"), sha256(b"upgraderail"));
        assert_ne!(sha256(b"upgraderail"), sha256(b"engine"));
    }
}
