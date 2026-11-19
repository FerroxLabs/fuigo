mod channel;
mod common;
mod gateway;
mod line_reader;
mod message;
mod normalize;
mod stdin_reader;

pub use self::{
    channel::{AcpAgentChannel, AcpChannel, AcpClientChannel, acp_channels, acp_send},
    common::{
        AcpAgentRx, AcpAgentTx, AcpChannelFailure, AcpClientRx, AcpClientTx, AcpResult, AcpRxo,
        AcpTxo, acp_channel_failure, acp_internal_error,
    },
    gateway::{
        AcpAgentGatewayReceiver, AcpAgentGatewaySender, AcpClientGatewayReceiver,
        AcpClientGatewaySender, AcpGatewayReceiver, AcpGatewaySender, acp_gateway,
    },
    message::{
        AcpAgentMessage, AcpAgentMessageBox, AcpAgentMessageGeneric, AcpArgs, AcpArgsBox,
        AcpClientMessage, AcpClientMessageBox, AcpClientMessageGeneric, AcpMethod, AcpRequest,
        AcpSide, Boxed, StorageMarker, Unboxed,
    },
};

pub use self::line_reader::LineBufferedRead;
pub use self::stdin_reader::spawn_stdin_line_reader;

#[doc(hidden)]
pub use self::common::compact_json;

/// Entry points for the fuzz targets in `fuzz/` (private line-handling functions); not a supported API.
#[doc(hidden)]
pub mod fuzz_support {
    pub fn normalize_json_line(line: Vec<u8>) -> Vec<u8> {
        crate::normalize::normalize_json_line(line)
    }

    pub fn read_until_capped<R: std::io::BufRead>(
        reader: &mut R,
        buf: &mut Vec<u8>,
        max: usize,
    ) -> std::io::Result<usize> {
        crate::stdin_reader::read_until_capped(reader, buf, max)
    }
}
