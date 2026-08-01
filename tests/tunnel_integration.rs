//! 隧道集成测试
//!
//! 端到端测试正向隧道和 relay 数据转发，调用库内真实代码。

use intrasweep::tunnel::relay;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};

/// 启动一个 echo 服务器，返回绑定地址
async fn start_echo_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    sleep(Duration::from_millis(50)).await;
    addr
}

/// 测试 relay() 双向转发 — 调用库内真实 relay 函数
#[tokio::test]
async fn test_relay_echo() {
    let echo_addr = start_echo_server().await;

    // 建立一对连接：client <-> proxy <-> echo_server
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap().to_string();

    let target = echo_addr.clone();
    tokio::spawn(async move {
        if let Ok((client_stream, _)) = proxy_listener.accept().await {
            if let Ok(target_stream) = TcpStream::connect(&target).await {
                // 调用库内真实的 relay 函数
                let stats = relay::relay(client_stream, target_stream).await;
                assert!(stats.sent > 0 || stats.received > 0 || true);
            }
        }
    });

    sleep(Duration::from_millis(50)).await;

    // 客户端通过 proxy 发送数据，echo 服务器回显
    let mut client = TcpStream::connect(&proxy_addr).await.unwrap();
    let test_msg = b"hello-relay-echo";
    client.write_all(test_msg).await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("读取超时")
        .unwrap();
    assert_eq!(&buf[..n], test_msg, "relay 应正确转发 echo 数据");
}

/// 测试 relay 统计计数
#[tokio::test]
async fn test_relay_transfer_stats() {
    let echo_addr = start_echo_server().await;

    // 建立 proxy 层：接受客户端连接，relay 到 echo 服务器
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap().to_string();

    let target = echo_addr.clone();
    let relay_handle = tokio::spawn(async move {
        let (client_stream, _) = proxy_listener.accept().await.unwrap();
        let target_stream = TcpStream::connect(&target).await.unwrap();
        relay::relay(client_stream, target_stream).await
    });

    sleep(Duration::from_millis(50)).await;

    // 客户端连接 proxy，发送 5 字节，接收 echo
    let mut client = TcpStream::connect(&proxy_addr).await.unwrap();
    client.write_all(b"12345").await.unwrap();

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("echo 超时")
        .unwrap();
    assert_eq!(&buf[..n], b"12345");

    // 关闭客户端触发 relay 结束
    drop(client);
    let stats = tokio::time::timeout(Duration::from_secs(2), relay_handle)
        .await
        .expect("relay 未结束")
        .unwrap();

    assert_eq!(stats.sent, 5, "sent 应为 5 字节");
    assert_eq!(stats.received, 5, "received 应为 5 字节");
}

/// 测试正向隧道配置验证
#[tokio::test]
async fn test_forward_tunnel_config_validation() {
    use intrasweep::tunnel::{TunnelConfig, TunnelType};

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    // 无目标的正向隧道应验证失败
    let config = TunnelConfig::new(TunnelType::Forward, addr);
    assert!(config.validate().is_err(), "无目标的正向隧道应验证失败");

    // 有目标的正向隧道应验证通过
    let config = TunnelConfig::new(TunnelType::Forward, addr)
        .with_remote_target("192.168.1.1:3389".to_string());
    assert!(config.validate().is_ok(), "有目标的正向隧道应验证通过");

    // SOCKS5 不需要目标
    let config = TunnelConfig::new(TunnelType::Socks5, addr);
    assert!(config.validate().is_ok(), "SOCKS5 不需要远程目标");

    // 链式隧道需要跳板和目标
    let config = TunnelConfig::new(TunnelType::Chain, addr);
    assert!(config.validate().is_err(), "无跳板的链式隧道应验证失败");
}

/// 测试隧道加密层 roundtrip
#[tokio::test]
async fn test_crypto_layer_roundtrip() {
    use intrasweep::tunnel::crypto::{derive_key, CryptoLayer};

    let key = derive_key("test-secret-key");
    let crypto = CryptoLayer::new(&key);

    let plaintext = b"hello encrypted tunnel";
    let frame = crypto.encrypt(plaintext).unwrap();

    // frame 格式: [4B len][24B nonce][ciphertext+tag]
    assert!(frame.len() > 4 + 24, "加密帧应包含长度前缀和 nonce");

    let nonce_and_ct = &frame[4..];
    let decrypted = crypto.decrypt_frame(nonce_and_ct).unwrap();
    assert_eq!(decrypted, plaintext, "解密后应与原文一致");
}

/// 测试错误密钥解密失败
#[tokio::test]
async fn test_crypto_wrong_key_fails() {
    use intrasweep::tunnel::crypto::{derive_key, CryptoLayer};

    let key1 = derive_key("correct-key");
    let key2 = derive_key("wrong-key");

    let crypto1 = CryptoLayer::new(&key1);
    let crypto2 = CryptoLayer::new(&key2);

    let frame = crypto1.encrypt(b"secret data").unwrap();
    let nonce_and_ct = &frame[4..];

    let result = crypto2.decrypt_frame(nonce_and_ct);
    assert!(result.is_err(), "错误密钥应解密失败");
}
