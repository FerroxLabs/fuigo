//! The pure decisions of the Windows inbox (packet 15c). Compiled and tested on every OS; nothing here touches the OS.
//!
//! - [`disabled_of`]: `WinUnavailable` to `Disabled`, one fixed reason per case.
//! - [`classify`]: `WinDialError` to the typed outcome a dial produces (the one mapping; the reaper, the list, the send and the
//!   watch probe all go through it).
//! - [`win_reap_decision`]: a row is reaped only when TWO tries both say the pipe does not exist.
//! - row edits on byte buffers: add ours (capacity rule), remove ours, remove exactly the rows read, the rows of others.
#![cfg_attr(not(windows), allow(dead_code))]

use std::time::Duration;

use fuigo_peer::locator_row::MAX_ROWS;
use fuigo_peer::{DeliveryOutcome, HostId, HostRow, RejectReason, TryResult};

use super::Disabled;
use super::rows::{decode_rows, encode_rows};
use super::win_policy::{WinDialError, WinUnavailable};

/// The gap between the two tries of a reap (same as unix).
pub(crate) const TRY_GAP: Duration = Duration::from_secs(1);
/// Probes in flight at once.
pub(crate) const MAX_PROBES: usize = 8;
/// One probe is cut off after this long; the try then counts as a timeout, which never condemns a row.
pub(crate) const PROBE_CAP: Duration = Duration::from_secs(3);
/// The whole reap pass at start is cut off after this long.
pub(crate) const REAP_BUDGET: Duration = Duration::from_secs(5);

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReapReport {
    pub reaped: Vec<HostId>,
    pub kept: usize,
}

/// A pipe-start failure as the `Disabled` reason it shows. The Win32 code of `CreateFailed` is dropped: the text is fixed.
pub(crate) fn disabled_of(u: WinUnavailable) -> Disabled {
    match u {
        WinUnavailable::FeatureOff => Disabled::FeatureOff,
        WinUnavailable::NotWindows => Disabled::UnsupportedPlatform,
        WinUnavailable::IdentityUnreadable => Disabled::IdentityUnreadable,
        WinUnavailable::NetworkLogon => Disabled::NetworkLogon,
        WinUnavailable::NameInUse => Disabled::PipeNameInUse,
        WinUnavailable::CreateFailed(_) => Disabled::PipeCreateFailed,
        WinUnavailable::ReadbackFailed => Disabled::PipeCheckFailed,
    }
}

/// What a failed dial amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialClass {
    /// The pipe does not exist (`ERROR_FILE_NOT_FOUND` on open): the only class that is evidence of an absent host.
    Gone,
    /// The pipe is busy, or the exchange ran out of time. Never evidence of death.
    Timeout,
    /// The peer speaks another protocol version. Never evidence of death.
    VersionMismatch,
    /// Everything else: a refusal by policy, access denied, a wrong server or hello, a bad frame, an unreadable identity.
    Unavailable,
}

pub(crate) fn classify(e: &WinDialError) -> DialClass {
    match e {
        WinDialError::NoServer => DialClass::Gone,
        WinDialError::Timeout => DialClass::Timeout,
        WinDialError::VersionMismatch => DialClass::VersionMismatch,
        WinDialError::IdentityUnreadable
        | WinDialError::NotAPipe
        | WinDialError::WrongServer(_)
        | WinDialError::ForeignHello
        | WinDialError::Other => DialClass::Unavailable,
    }
}

impl DialClass {
    /// The reap-table result of a try that failed this way.
    pub(crate) fn try_result(self) -> TryResult {
        match self {
            Self::Gone => TryResult::NoSuchFile,
            Self::Timeout => TryResult::Timeout,
            Self::VersionMismatch => TryResult::VersionMismatch,
            Self::Unavailable => TryResult::Other,
        }
    }

    /// The outcome a send reports when its dial failed this way: the same one the unix path reports for every failure.
    pub(crate) fn delivery(self) -> DeliveryOutcome {
        DeliveryOutcome::Rejected { reason: RejectReason::Unavailable }
    }
}

/// Reap rule on Windows: no file exists to unlink, so liveness is the pipe itself. A row goes only when BOTH tries found
/// no pipe of that name. A busy pipe, access denied, a refusal, a version mismatch, a timeout, a hello of anyone, or any
/// other failure keeps it.
pub(crate) fn win_reap_decision(first: &TryResult, second: &TryResult) -> bool {
    matches!((first, second), (TryResult::NoSuchFile, TryResult::NoSuchFile))
}

/// The locator already holds the maximum number of rows of other hosts.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Full;

/// `cur` with our row added (an older row of the same host id replaced). `Err(Full)` when the locator already holds the
/// maximum number of rows of other hosts: nothing to write.
pub(crate) fn with_row_added(cur: Option<&[u8]>, mine: HostRow) -> Result<Option<Vec<u8>>, Full> {
    let mut rows = decode_rows(cur);
    rows.retain(|r| r.host_id != mine.host_id);
    if rows.len() >= MAX_ROWS {
        return Err(Full);
    }
    rows.push(mine);
    Ok(encode_rows(&rows))
}

/// `cur` without the row of `host` (and with every other row untouched). Unchanged bytes when there was no such row.
pub(crate) fn without_host(cur: Option<&[u8]>, host: &HostId) -> Option<Vec<u8>> {
    let mut rows = decode_rows(cur);
    let before = rows.len();
    rows.retain(|r| &r.host_id != host);
    if rows.len() == before {
        return cur.map(<[u8]>::to_vec);
    }
    encode_rows(&rows)
}

/// `cur` without exactly the `victims` that are still present unchanged (same host id, pid, start marker and dir), and the
/// host ids actually removed. A changed or gone row is left alone.
pub(crate) fn without_exact(cur: Option<&[u8]>, victims: &[HostRow]) -> (Option<Vec<u8>>, Vec<HostId>) {
    let mut rows = decode_rows(cur);
    let mut removed = Vec::new();
    for v in victims {
        if let Some(i) = rows.iter().position(|r| r == v) {
            rows.remove(i);
            removed.push(v.host_id.clone());
        }
    }
    if removed.is_empty() {
        return (cur.map(<[u8]>::to_vec), removed);
    }
    (encode_rows(&rows), removed)
}

/// The rows of other hosts, at most `cap`.
pub(crate) fn others(cur: Option<&[u8]>, own: &HostId, cap: usize) -> Vec<HostRow> {
    let mut rows = decode_rows(cur);
    rows.retain(|r| &r.host_id != own);
    rows.truncate(cap);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_peer::HostDir;

    fn hid(c: char) -> HostId {
        HostId::new(&c.to_string().repeat(32)).unwrap()
    }

    fn row(c: char, pid: u32) -> HostRow {
        HostRow { host_id: hid(c), pid, started: 100, dir: HostDir::Home }
    }

    fn bytes(rows: &[HostRow]) -> Vec<u8> {
        encode_rows(rows).unwrap()
    }

    #[test]
    fn dial_error_table() {
        use super::super::win_policy::ServerRefusal;
        let cases = [
            (WinDialError::NoServer, DialClass::Gone, TryResult::NoSuchFile),
            (WinDialError::Timeout, DialClass::Timeout, TryResult::Timeout),
            (WinDialError::VersionMismatch, DialClass::VersionMismatch, TryResult::VersionMismatch),
            (WinDialError::IdentityUnreadable, DialClass::Unavailable, TryResult::Other),
            (WinDialError::NotAPipe, DialClass::Unavailable, TryResult::Other),
            (WinDialError::WrongServer(ServerRefusal::NotAPipe), DialClass::Unavailable, TryResult::Other),
            (WinDialError::ForeignHello, DialClass::Unavailable, TryResult::Other),
            (WinDialError::Other, DialClass::Unavailable, TryResult::Other),
        ];
        for (e, class, tr) in cases {
            assert_eq!(classify(&e), class, "{e:?}");
            assert_eq!(class.try_result(), tr, "{e:?}");
            assert_eq!(class.delivery(), DeliveryOutcome::Rejected { reason: RejectReason::Unavailable }, "{e:?}");
        }
    }

    #[test]
    fn reap_needs_two_absent_pipes_and_nothing_else_reaps() {
        let id = hid('a');
        let all = [
            TryResult::Refused,
            TryResult::NoSuchFile,
            TryResult::Timeout,
            TryResult::VersionMismatch,
            TryResult::Hello(id.clone()),
            TryResult::Hello(hid('b')),
            TryResult::Other,
        ];
        for a in &all {
            for b in &all {
                let want = matches!((a, b), (TryResult::NoSuchFile, TryResult::NoSuchFile));
                assert_eq!(win_reap_decision(a, b), want, "{a:?} then {b:?}");
            }
        }
    }

    #[test]
    fn unavailable_reasons_map_to_fixed_texts() {
        let cases = [
            (WinUnavailable::FeatureOff, Disabled::FeatureOff),
            (WinUnavailable::NotWindows, Disabled::UnsupportedPlatform),
            (WinUnavailable::IdentityUnreadable, Disabled::IdentityUnreadable),
            (WinUnavailable::NetworkLogon, Disabled::NetworkLogon),
            (WinUnavailable::NameInUse, Disabled::PipeNameInUse),
            (WinUnavailable::CreateFailed(5), Disabled::PipeCreateFailed),
            (WinUnavailable::CreateFailed(1234), Disabled::PipeCreateFailed),
            (WinUnavailable::ReadbackFailed, Disabled::PipeCheckFailed),
        ];
        for (u, d) in cases {
            assert_eq!(disabled_of(u), d, "{u:?}");
            assert_eq!(d.reason_text(), u.reason_text(), "{u:?}: same fixed text on both sides");
        }
        assert!(Disabled::NetworkLogon.reason_text().contains("remote (network) logon session"));
    }

    #[test]
    fn add_replaces_own_row_keeps_others_and_refuses_when_full() {
        let a = row('a', 1);
        let first = with_row_added(None, a.clone()).unwrap().unwrap();
        assert_eq!(decode_rows(Some(&first)), vec![a.clone()]);
        let a2 = row('a', 2);
        let b = row('b', 3);
        let cur = bytes(&[a.clone(), b.clone()]);
        let next = with_row_added(Some(&cur), a2.clone()).unwrap().unwrap();
        assert_eq!(decode_rows(Some(&next)), vec![b.clone(), a2]);
        // a garbage file counts as no rows
        let g = with_row_added(Some(b"not json"), a.clone()).unwrap().unwrap();
        assert_eq!(decode_rows(Some(&g)), vec![a.clone()]);
        // full of other hosts
        let full: Vec<HostRow> = (0..MAX_ROWS)
            .map(|i| HostRow { host_id: HostId::new(&format!("{i:032x}")).unwrap(), pid: i as u32, started: 1, dir: HostDir::Home })
            .collect();
        let cur = bytes(&full);
        assert!(with_row_added(Some(&cur), a).is_err());
    }

    #[test]
    fn remove_own_only_and_remove_exact_only_unchanged_rows() {
        let (a, b) = (row('a', 1), row('b', 2));
        let cur = bytes(&[a.clone(), b.clone()]);
        let left = without_host(Some(&cur), &hid('a')).unwrap();
        assert_eq!(decode_rows(Some(&left)), vec![b.clone()]);
        // last row removed: the file goes
        assert!(without_host(Some(&left), &hid('b')).is_none());
        // not present: bytes unchanged
        assert_eq!(without_host(Some(&cur), &hid('9')).unwrap(), cur);
        assert_eq!(without_host(Some(b"garbage"), &hid('a')).unwrap(), b"garbage".to_vec());
        // exact: a row restarted under the same host id (other pid or start marker) is not removed
        let restarted = row('a', 99);
        let (out, removed) = without_exact(Some(&cur), &[restarted]);
        assert!(removed.is_empty());
        assert_eq!(out.unwrap(), cur);
        let (out, removed) = without_exact(Some(&cur), std::slice::from_ref(&a));
        assert_eq!(removed, vec![hid('a')]);
        assert_eq!(decode_rows(out.as_deref()), vec![b]);
        // others
        assert_eq!(others(Some(&cur), &hid('a'), 8).len(), 1);
        assert_eq!(others(Some(&cur), &hid('a'), 0).len(), 0);
        assert!(others(Some(b"junk"), &hid('a'), 8).is_empty());
        assert!(others(None, &hid('a'), 8).is_empty());
    }
}
