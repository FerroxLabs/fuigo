//! Size and count constants fixed by the design (section 3, S3.2, S5, S7).

/// Largest message body (S5.1). The sender refuses first, the receiver again.
pub const MAX_BODY_BYTES: usize = 32 * 1024;
/// Largest inbox frame (S3.2, S5.1).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Rows per `list` page (S3.2).
pub const LIST_PAGE_ROWS: usize = 64;
/// Hosts asked by one `list_agents` call (section 2, row 2).
pub const MAX_LIST_HOSTS: usize = 64;
/// Rows returned by one `list_agents` call (section 2, row 2).
pub const MAX_LIST_ROWS: usize = 256;
/// Queued-or-held messages per session (S5.2).
pub const MAX_MESSAGES_PER_SESSION: usize = 64;
/// Bytes of queued-or-held bodies per session (S5.2).
pub const MAX_BODY_BYTES_PER_SESSION: usize = 1024 * 1024;
/// Queued-or-held messages per host (S5.2).
pub const MAX_MESSAGES_PER_HOST: usize = 256;
/// Bytes of queued-or-held bodies per host (S5.2).
pub const MAX_BODY_BYTES_PER_HOST: usize = 4 * 1024 * 1024;
/// Messages per minute per sender-receiver pair (S5.3).
pub const RATE_PER_PAIR_PER_MINUTE: u32 = 10;
/// Messages per minute per receiving host (S5.3).
pub const RATE_PER_HOST_PER_MINUTE: u32 = 60;
/// Entries in the rate table (S5.3).
pub const RATE_TABLE_ENTRIES: usize = 1024;
/// Remembered message ids for idempotency (S5.4).
pub const REMEMBERED_MESSAGE_IDS: usize = 1024;
/// Seconds a message id is remembered (S5.4): 10 minutes.
pub const MESSAGE_ID_MEMORY_SECS: u64 = 10 * 60;
/// Seconds a hold lasts (S5.5): 5 minutes.
pub const HOLD_EXPIRY_SECS: u64 = 5 * 60;
/// Seconds a watch lasts (S5.5): 12 hours.
pub const WATCH_EXPIRY_SECS: u64 = 12 * 60 * 60;
/// Armed watches per receiving session (S5.5, S9.1); past it the oldest is ended with an `unavailable` notice.
pub const MAX_WATCHES_PER_SESSION: usize = 64;
/// Armed watches per receiving host.
pub const MAX_WATCHES_PER_HOST: usize = 256;
/// Seconds between the sender host's probes of each watched target host (S9.2).
pub const WATCH_PROBE_SECS: u64 = 60;
/// Probes in flight at once, and the cap of each (milliseconds).
pub const WATCH_PROBES_AT_ONCE: usize = 8;
pub const WATCH_PROBE_CAP_MS: u64 = 3000;
/// Hop at which the receiver holds with `loop_guard` (S5.6).
pub const HOP_BUDGET: u32 = 8;
/// Turns a session may start from peer input since its last human prompt (S5.6).
pub const PEER_TURN_BUDGET: u32 = 20;
/// Permission denials a session remembers (S7.1).
pub const DENIAL_RING: usize = 16;
/// Keys one denial may hold (S7.1): a multi-target action keys each target, up to this many.
pub const MAX_KEYS_PER_DENIAL: usize = 8;
/// Denial stamps one envelope may carry (S7.2): every key of every remembered denial, `DENIAL_RING` x `MAX_KEYS_PER_DENIAL`.
pub const MAX_DENIAL_STAMPS: usize = DENIAL_RING * MAX_KEYS_PER_DENIAL;
/// Denial keys a receiving session carries in total (S7.3): one full envelope. When full the newest is dropped and counted.
pub const MAX_CARRIED_KEYS: usize = MAX_DENIAL_STAMPS;
/// Seconds after a denial during which sends are stamped `denied-recently` (S7.2): 30 minutes.
pub const DENIAL_STAMP_SECS: u64 = 30 * 60;
/// Longest `from-name` (S1.7), in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Longest session id or incarnation text accepted in an address.
pub const MAX_ADDRESS_SESSION_ID_CHARS: usize = 128;
/// Longest `reason` on `refuse_peer_message`, in bytes.
pub const MAX_REFUSE_REASON_BYTES: usize = 1024;
/// Longest `summary` on `send_message`, in bytes. The summary never leaves the sender.
pub const MAX_SUMMARY_BYTES: usize = 512;
/// Longest `to` on `send_message`, in bytes (an address is at most ~190; a 64-character name is at most 256 bytes plus a ref).
pub const MAX_TO_BYTES: usize = 512;
/// Longest identifier field (`message_id`, `conversation_id`, `from_ref`) in an envelope, in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Longest `tool_kind` or `target_hash` in a denial stamp, in bytes.
pub const MAX_DENIAL_FIELD_BYTES: usize = 128;
