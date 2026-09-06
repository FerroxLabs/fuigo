#![cfg(not(target_arch = "wasm32"))]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn read_frame(stream: &mut tokio::net::TcpStream) -> std::io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut header = [0_u8; 9];
    stream.read_exact(&mut header).await?;
    let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).await?;
    let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
    Ok((header[3], header[4], stream_id, payload))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_empty_frames_are_bounded() {
    const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];
    const SETTINGS_ACK: &[u8] = &[0, 0, 0, 4, 1, 0, 0, 0, 0];
    const RESPONSE_HEADERS: &[u8] = &[0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88];
    const EMPTY_DATA: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 1];
    const ENHANCE_YOUR_CALM: u32 = 0x0b;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (start_attack_tx, start_attack_rx) = tokio::sync::oneshot::channel();

    let hostile_server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut preface = vec![0_u8; CLIENT_PREFACE.len()];
        socket.read_exact(&mut preface).await.unwrap();
        assert_eq!(preface, CLIENT_PREFACE);

        let (frame_type, _, stream_id, _) = read_frame(&mut socket).await.unwrap();
        assert_eq!((frame_type, stream_id), (4, 0), "client SETTINGS first");
        socket.write_all(SETTINGS).await.unwrap();
        socket.write_all(SETTINGS_ACK).await.unwrap();

        loop {
            let (frame_type, _, stream_id, _) = read_frame(&mut socket).await.unwrap();
            if frame_type == 1 && stream_id == 1 {
                break;
            }
        }
        socket.write_all(RESPONSE_HEADERS).await.unwrap();
        socket.flush().await.unwrap();

        start_attack_rx.await.unwrap();
        for _ in 0..128 {
            if socket.write_all(EMPTY_DATA).await.is_err() {
                break;
            }
        }
        let _ = socket.flush().await;

        let error_code = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (frame_type, _, stream_id, payload) = read_frame(&mut socket).await.unwrap();
                if frame_type == 7 {
                    assert_eq!(stream_id, 0);
                    assert!(payload.len() >= 8);
                    break u32::from_be_bytes(payload[4..8].try_into().unwrap());
                }
            }
        })
        .await
        .expect("client must reject the bounded empty-DATA attack");
        assert_eq!(error_code, ENHANCE_YOUR_CALM);
    });

    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let response = client
        .get(format!("http://{addr}/"))
        .send()
        .await
        .expect("receive response headers");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Hold the response body undrained while the peer emits the hostile sequence. The patched h2
    // budget must reject it instead of growing an unbounded queue of empty body events.
    start_attack_tx.send(()).unwrap();
    hostile_server.await.unwrap();
    drop(response);
}
