//! The locator row format, shared by every platform (unix `reap`/`inbox` and the Windows inbox).

use fuigo_peer::{HostRow, parse_rows};

/// The locator file inside the peers directory.
pub(crate) const LOCATOR_NAME: &str = "hosts.json";

/// Serialize rows the way `parse_rows` reads them; `None` (remove the file) when there are none.
pub(crate) fn encode_rows(rows: &[HostRow]) -> Option<Vec<u8>> {
    if rows.is_empty() { None } else { serde_json::to_vec(rows).ok() }
}

/// Parse an existing file's bytes; a file that does not parse counts as no rows (it is rewritten, S3.4).
pub(crate) fn decode_rows(cur: Option<&[u8]>) -> Vec<HostRow> {
    cur.and_then(|b| parse_rows(b).ok()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_rows_means_remove_and_garbage_means_no_rows() {
        assert_eq!(LOCATOR_NAME, "hosts.json");
        assert!(encode_rows(&[]).is_none());
        assert!(decode_rows(None).is_empty());
        assert!(decode_rows(Some(b"not json")).is_empty());
        assert!(decode_rows(Some(b"[]")).is_empty());
    }
}
