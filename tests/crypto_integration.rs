//! 加密流集成测试
//!
//! 测试 EncryptedStream 通过 tokio duplex 通道的往返加解密。

use intrasweep::tunnel::crypto::{derive_key, CryptoLayer, EncryptedStream};
use std::sync::Arc;
use tokio::io::{duplex, AsyncReadExt};

#[tokio::test]
async fn test_encrypted_stream_roundtrip() {
    let key = derive_key("integration-test-key");
    let crypto = Arc::new(CryptoLayer::new(&key));

    let (client, server) = duplex(65536);

    let crypto_clone = crypto.clone();
    let mut encrypted_client = EncryptedStream::new(client, crypto_clone);
    let mut encrypted_server = EncryptedStream::new(server, crypto);

    // 客户端写入加密数据
    let msg = b"Hello from encrypted tunnel!";
    encrypted_client.write_frame(msg).await.unwrap();

    // 服务端读取解密数据
    let mut buf = vec![0u8; 1024];
    let n = encrypted_server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], msg);

    // 服务端回复
    let reply = b"ACK from server";
    encrypted_server.write_frame(reply).await.unwrap();

    // 客户端读取回复
    let n = encrypted_client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], reply);
}

#[tokio::test]
async fn test_encrypted_stream_large_data() {
    let key = derive_key("large-data-test");
    let crypto = Arc::new(CryptoLayer::new(&key));

    let (client, server) = duplex(65536);
    let mut encrypted_client = EncryptedStream::new(client, crypto.clone());
    let mut encrypted_server = EncryptedStream::new(server, crypto);

    // 发送较大数据（需多帧）
    let data = vec![0x42u8; 10000];
    encrypted_client.write_frame(&data).await.unwrap();

    let mut buf = vec![0u8; 20000];
    let n = encrypted_server.read(&mut buf).await.unwrap();
    assert_eq!(n, data.len());
    assert_eq!(&buf[..n], &data[..]);
}

#[tokio::test]
async fn test_encrypted_stream_multiple_frames() {
    let key = derive_key("multi-frame-test");
    let crypto = Arc::new(CryptoLayer::new(&key));

    let (client, server) = duplex(65536);
    let mut encrypted_client = EncryptedStream::new(client, crypto.clone());
    let mut encrypted_server = EncryptedStream::new(server, crypto);

    for i in 0..5 {
        let msg = format!("message-{}", i);
        encrypted_client.write_frame(msg.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = encrypted_server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
    }
}
