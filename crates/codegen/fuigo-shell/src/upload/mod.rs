pub(crate) mod feedback_archive;
pub use feedback_archive::scrub_upload_text;

/// P149 (S14/K16): install [`scrub_upload_text`] as this process's storage-upload filter
/// (`fuigo_file_utils::payload_filter`), so every upload primitive and the upload queue's worker apply it to text.
/// Idempotent; called where an agent is built, where the upload queue is spawned and by `fuigo trace`.
pub fn install_upload_scrub() {
    fuigo_file_utils::payload_filter::install(scrub_upload_text);
    // Astra r2 #2: a gzipped tar the queue uploads (a memory archive spilled before this fix and recovered at
    // startup) gets its text members scrubbed too; a gzip that is not a tar is sent as it is.
    fuigo_file_utils::payload_filter::install_archive(|archive| {
        feedback_archive::scrub_upload_tar_gz(archive).ok()
    });
}
pub mod gcs;
pub(crate) mod manifest;
pub(crate) mod memory;
pub(crate) mod trace;
pub(crate) mod turn;
#[cfg(test)]
mod p71_gate_tests;
