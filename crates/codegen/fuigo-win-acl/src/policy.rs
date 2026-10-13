//! The pure part of the file rule: plain data in, a verdict out. Compiled and tested on every OS.
//! Moved unchanged from `fuigo-shell` (`peer_inbox/win_policy.rs`) so `fuigo-mcp` can use the same rule.

/// One ACE of the DACL read back from the pipe: type, flags and trustee, as the OS rendered them in SDDL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AceSummary {
    pub kind: String,
    pub flags: String,
    /// The access mask as the OS rendered it in SDDL (`GA`, `FA`, `GRGW`, `0x...`).
    pub rights: String,
    pub trustee: String,
}

/// The DACL of the pipe instance as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaclSummary {
    /// The DACL control flags text (`P` = protected, `AI` = auto-inherited, ...).
    pub flags: String,
    pub aces: Vec<AceSummary>,
}

/// Text that looks like a SID: `S-1-` then digits and dashes only, 5 to 184 characters, no empty part.
pub fn is_sid_text(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("S-1-") else {
        return false;
    };
    s.len() <= 184
        && !rest.is_empty()
        && rest.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// One ACE as read from the binary ACL (`GetAce`): numeric type, flags and mask, and the trustee as a FULL SID string
/// (`ConvertSidToStringSidW`, which never renders aliases such as `LA`, `LG`, `BA`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAce {
    pub ace_type: u8,
    pub flags: u8,
    pub mask: u32,
    pub trustee_sid: String,
}

/// Build the [`DaclSummary`] the policy judges from the binary descriptor: `protected` is the `SE_DACL_PROTECTED` control
/// bit (not SDDL text). ACCESS_ALLOWED_ACE_TYPE (0) is `A`; any other type is its hex number, which never matches.
/// Flags are empty when zero, else hex (so any inherit or audit flag fails). The mask is `0x...` lowercase hex.
pub fn dacl_summary_from_binary(protected: bool, aces: &[RawAce]) -> DaclSummary {
    DaclSummary {
        flags: if protected { "P".to_owned() } else { String::new() },
        aces: aces
            .iter()
            .map(|a| AceSummary {
                kind: if a.ace_type == 0 { "A".to_owned() } else { format!("0x{:x}", a.ace_type) },
                flags: if a.flags == 0 { String::new() } else { format!("0x{:x}", a.flags) },
                rights: format!("0x{:x}", a.mask),
                trustee: a.trustee_sid.clone(),
            })
            .collect(),
    }
}

pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";

/// May this owner own a locator file? Us; BUILTIN\Administrators only when our token is elevated (Windows gives such a
/// process that owner by default).
pub fn locator_owner_ok(owner: &str, ours: &str, elevated: bool) -> bool {
    is_sid_text(ours) && (owner == ours || (elevated && owner == SID_ADMINISTRATORS))
}

/// May this DACL guard a locator file? Every ACE is a plain allow (no deny, no object ACE, no audit or inherit-only
/// flag; the inherited flag alone is fine) for us, SYSTEM or BUILTIN\Administrators. Anyone else makes it fail.
pub fn locator_dacl_ok(d: &DaclSummary, ours: &str) -> bool {
    is_sid_text(ours)
        && d.aces.iter().all(|a| {
            a.kind == "A"
                && (a.flags.is_empty() || a.flags == "0x10")
                && (a.trustee == ours || a.trustee == SID_SYSTEM || a.trustee == SID_ADMINISTRATORS)
        })
}

/// The SDDL a file or pipe is created with: owner = us, protected DACL, ONE allow ACE for us, nothing inherited, no SYSTEM.
/// Moved from `fuigo-shell` (`peer_inbox/win_policy.rs`); the test helpers here build files with it.
pub fn owner_only_sddl(user_sid: &str) -> Option<String> {
    is_sid_text(user_sid).then(|| format!("O:{user_sid}D:P(A;;GA;;;{user_sid})"))
}

#[cfg(test)]
mod locator_policy_tests {
    use super::*;

    const ME: &str = "S-1-5-21-1-2-3-1001";

    fn ace(kind: &str, flags: &str, who: &str) -> AceSummary {
        AceSummary { kind: kind.into(), flags: flags.into(), rights: "0x1f01ff".into(), trustee: who.into() }
    }

    #[test]
    fn owner_rule() {
        assert!(locator_owner_ok(ME, ME, false));
        assert!(!locator_owner_ok(SID_ADMINISTRATORS, ME, false));
        assert!(locator_owner_ok(SID_ADMINISTRATORS, ME, true));
        assert!(!locator_owner_ok("S-1-5-32-545", ME, true));
        assert!(!locator_owner_ok(ME, "junk", true));
    }

    #[test]
    fn dacl_rule() {
        let d = |aces| DaclSummary { flags: "P".into(), aces };
        assert!(locator_dacl_ok(&d(vec![ace("A", "", ME)]), ME));
        assert!(locator_dacl_ok(&d(vec![ace("A", "0x10", ME), ace("A", "0x10", SID_SYSTEM), ace("A", "", SID_ADMINISTRATORS)]), ME));
        assert!(locator_dacl_ok(&d(vec![]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("A", "", ME), ace("A", "", "S-1-5-32-545")]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("A", "", "S-1-1-0")]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("0x1", "", ME)]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("A", "0x8", ME)]), ME));
        assert!(!locator_dacl_ok(&d(vec![ace("A", "", ME)]), "junk"));
    }

    #[test]
    fn sid_text_check() {
        assert!(is_sid_text(ME));
        assert!(is_sid_text("S-1-5-18"));
        for bad in ["", "S-1-", "S-1--5", "S-2-5-18", "s-1-5-18", "S-1-5-18\\x", "S-1-5-1a", "S-1-5-18 ", "S-1-5-\u{660}"] {
            assert!(!is_sid_text(bad), "{bad:?}");
        }
        assert!(!is_sid_text(&format!("S-1-{}", "5-".repeat(100) + "1")));
    }
}
