//! This adapter translates fuigo-tools' `AsyncFileSystem` trait into ACP protocol calls:
//!   `read_file()` → read_text_file
//!   `write_file()` → write_text_file
//!   `delete_file()` → not supported by ACP (returns error)
//!
//! It mirrors the pattern of `AcpTerminalAdapter` for terminal execution.

use std::path::Path;

use agent_client_protocol as acp;
use fuigo_acp_lib::AcpAgentGatewaySender as GatewaySender;
use fuigo_tools::computer::types::{AsyncFileSystem, ComputerError};

/// Wraps fuigo-shell's ACP gateway to satisfy fuigo-tools' AsyncFileSystem.
///
/// When a client advertises `clientCapabilities.fs.readTextFile` and `writeTextFile`, tools stop hitting the local disk directly.
/// File operations (read_file, search_replace, etc.) are routed through the ACP gateway back to the client.
pub struct AcpFsAdapter {
    gateway: GatewaySender,
    session_id: acp::SessionId,
}

impl AcpFsAdapter {
    pub fn new(gateway: GatewaySender, session_id: acp::SessionId) -> Self {
        Self {
            gateway,
            session_id,
        }
    }
}

#[async_trait::async_trait]
impl AsyncFileSystem for AcpFsAdapter {
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, ComputerError> {
        let read_req = acp::ReadTextFileRequest::new(self.session_id.clone(), path.to_path_buf());

        let response = self
            .gateway
            .send(read_req)
            .await
            .map_err(acp_error_to_computer_error)?;

        Ok(response.content.into_bytes())
    }

    /// P166/S12: the client owns the file system (it decides what a regular file is) and returns the whole text in one
    /// response, so the cap is enforced on what the tools accept: an over-cap response is refused, never processed.
    fn supports_bounded_read(&self) -> bool {
        true
    }

    async fn read_file_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ComputerError> {
        let bytes = self.read_file(path).await?;
        if bytes.len() > max_bytes {
            return Err(ComputerError::io_with_kind(
                format!("file exceeds the {max_bytes} byte read limit"),
                std::io::ErrorKind::FileTooLarge,
            ));
        }
        Ok(bytes)
    }

    async fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), ComputerError> {
        let content =
            String::from_utf8(data.to_vec()).map_err(|e| ComputerError::io(e.to_string()))?;

        let write_req =
            acp::WriteTextFileRequest::new(self.session_id.clone(), path.to_path_buf(), content);

        self.gateway
            .send(write_req)
            .await
            .map_err(acp_error_to_computer_error)?;

        Ok(())
    }

    async fn delete_file(&self, path: &Path) -> Result<(), ComputerError> {
        // ACP protocol doesn't support file deletion yet
        tracing::warn!(?path, "ACP filesystem does not support file deletion");
        Err(ComputerError::io("File deletion not supported via ACP"))
    }
}

fn acp_error_to_computer_error(err: acp::Error) -> ComputerError {
    match acp_error_to_io_kind(&err) {
        Some(kind) => ComputerError::io_with_kind(err.to_string(), kind),
        None => ComputerError::io(err.to_string()),
    }
}

fn acp_error_to_io_kind(err: &acp::Error) -> Option<std::io::ErrorKind> {
    let msg_lower = err.message.to_ascii_lowercase();

    if err.code == acp::ErrorCode::ResourceNotFound {
        Some(std::io::ErrorKind::NotFound)
    } else if msg_lower.contains("permission denied") {
        Some(std::io::ErrorKind::PermissionDenied)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P166/S12, Astra r1 HIGH: the ACP backend now takes the bounded path, and an over-cap client response is refused.
    #[tokio::test]
    async fn bounded_read_refuses_an_over_cap_response() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let adapter = AcpFsAdapter::new(GatewaySender::new(tx), acp::SessionId::new("p166"));
        let client = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let fuigo_acp_lib::AcpClientMessage::ReadTextFile(args) = message {
                    let _ = args
                        .response_tx
                        .send(Ok(acp::ReadTextFileResponse::new("abcdef")));
                }
            }
        });
        assert!(adapter.supports_bounded_read());
        assert_eq!(
            b"abcdef",
            adapter
                .read_file_bounded(Path::new("/x"), 6)
                .await
                .unwrap()
                .as_slice()
        );
        let error = adapter
            .read_file_bounded(Path::new("/x"), 5)
            .await
            .unwrap_err();
        assert_eq!(Some(std::io::ErrorKind::FileTooLarge), error.io_error_kind());
        drop(adapter);
        client.abort();
    }
}
