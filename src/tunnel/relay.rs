//! 双向流量转发公共模块
//!
//! 提供统一的 TCP 双向转发功能，被 forward/chain/socks5 模块共用。
//! 支持泛型流类型（TcpStream / EncryptedStream）。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing;

/// 数据传输统计
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferStats {
    pub sent: u64,
    pub received: u64,
}

/// 双向流量转发（泛型版本）
///
/// 在 client 和 target 之间进行双向数据转发，
/// 支持 TCP 半关闭：当某一方向收到 EOF 时，对另一方向的写端
/// 调用 `shutdown()` 通知对端，然后继续转发另一方向直到双向均结束。
/// 支持 `TcpStream`、`EncryptedStream` 等组合。
pub async fn relay<C, T>(client: C, target: T) -> TransferStats
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut target_read, mut target_write) = tokio::io::split(target);

    // client -> target 方向
    let c2t = async {
        let mut buf = vec![0u8; 32768];
        let mut total = 0u64;
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = target_write.write_all(&buf[..n]).await {
                        tracing::error!("写入目标失败: {}", e);
                        break;
                    }
                    total += n as u64;
                }
                Err(e) => {
                    tracing::error!("读取客户端失败: {}", e);
                    break;
                }
            }
        }
        // 半关闭：通知 target 端不会再有数据写入
        let _ = target_write.shutdown().await;
        total
    };

    // target -> client 方向
    let t2c = async {
        let mut buf = vec![0u8; 32768];
        let mut total = 0u64;
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        tracing::error!("写入客户端失败: {}", e);
                        break;
                    }
                    total += n as u64;
                }
                Err(e) => {
                    tracing::error!("读取目标失败: {}", e);
                    break;
                }
            }
        }
        // 半关闭：通知 client 端不会再有数据写入
        let _ = client_write.shutdown().await;
        total
    };

    let (sent, received) = tokio::join!(c2t, t2c);

    TransferStats { sent, received }
}
