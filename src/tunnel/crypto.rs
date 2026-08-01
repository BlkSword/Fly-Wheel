//! 隧道加密模块
//!
//! 提供基于 XChaCha20-Poly1305 AEAD 的加密传输层。
//! 借鉴 RedPivot crypto.go 的设计，用 Rust 生态重写。

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// 最大帧载荷（1 MB）
const MAX_FRAME: usize = 1024 * 1024;

/// 加密层 — 持有 XChaCha20-Poly1305 AEAD 密码实例
pub struct CryptoLayer {
    cipher: XChaCha20Poly1305,
}

impl CryptoLayer {
    /// 从 32 字节密钥创建加密层
    pub fn new(key: &[u8; 32]) -> Self {
        use chacha20poly1305::Key;
        let key = Key::from_slice(key);
        Self {
            cipher: XChaCha20Poly1305::new(key),
        }
    }

    /// 加密明文，返回完整帧: [4B len BE][24B nonce][ciphertext+tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = *XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| io::Error::other(format!("加密失败: {}", e)))?;

        let total_len = 24 + ciphertext.len();
        let mut frame = Vec::with_capacity(4 + total_len);
        frame.extend_from_slice(&(total_len as u32).to_be_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// 解密帧，输入不含 4 字节长度前缀
    pub fn decrypt_frame(&self, nonce_and_ct: &[u8]) -> io::Result<Vec<u8>> {
        if nonce_and_ct.len() < 24 + 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "帧数据过短，至少需要 nonce(24) + tag(16)",
            ));
        }
        let nonce = XNonce::from_slice(&nonce_and_ct[..24]);
        let ciphertext = &nonce_and_ct[24..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| io::Error::other(format!("解密失败: {}", e)))
    }
}

/// 加密流 — 包装异步流，透明加解密
///
/// 实现正确的 `AsyncRead` + `AsyncWrite`，可与 `tokio::io::copy`、
/// `relay` 等标准工具组合使用。
pub struct EncryptedStream<S> {
    inner: S,
    crypto: Arc<CryptoLayer>,
    /// 已解密的明文缓冲区
    read_buf: Vec<u8>,
    read_pos: usize,
    /// 帧读取状态机
    rd_state: RdState,
}

/// 帧读取状态
enum RdState {
    /// 空闲，准备读下一帧
    Idle,
    /// 正在读 4 字节长度头
    Header { pos: usize, hdr: [u8; 4] },
    /// 正在读 nonce + ciphertext
    Payload {
        pos: usize,
        len: usize,
        pkt: Vec<u8>,
    },
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedStream<S> {
    pub fn new(inner: S, crypto: Arc<CryptoLayer>) -> Self {
        Self {
            inner,
            crypto,
            read_buf: Vec::new(),
            read_pos: 0,
            rd_state: RdState::Idle,
        }
    }

    /// 获取内部流的引用
    #[allow(dead_code)]
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// 获取内部流的可变引用
    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// 写入加密帧（async 方法，用于需要直接写帧的场景）
    #[allow(dead_code)]
    pub async fn write_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = self.crypto.encrypt(data)?;
        self.inner.write_all(&frame).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        // 1. 返回已缓冲的明文
        if this.read_pos < this.read_buf.len() {
            let available = &this.read_buf[this.read_pos..];
            let n = available.len().min(buf.remaining());
            buf.put_slice(&available[..n]);
            this.read_pos += n;
            return Poll::Ready(Ok(()));
        }
        // 缓冲区已清空
        this.read_buf.clear();
        this.read_pos = 0;

        // 2. 驱动帧读取状态机（最多两阶段：Header → Payload）
        if matches!(this.rd_state, RdState::Idle) {
            this.rd_state = RdState::Header {
                pos: 0,
                hdr: [0u8; 4],
            };
        }

        if let RdState::Header { pos, hdr } = &mut this.rd_state {
            let remaining = &mut hdr.as_mut_slice()[*pos..];
            let mut h = ReadBuf::new(remaining);
            match Pin::new(&mut this.inner).poll_read(cx, &mut h) {
                Poll::Ready(Ok(())) => {
                    let filled = h.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    *pos += filled;
                    if *pos < 4 {
                        return Poll::Pending;
                    }
                    let payload_len = u32::from_be_bytes(*hdr) as usize;
                    if payload_len > MAX_FRAME {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("帧长度异常: {} 字节", payload_len),
                        )));
                    }
                    // 转换到 Payload 阶段
                    this.rd_state = RdState::Payload {
                        pos: 0,
                        len: payload_len,
                        pkt: vec![0u8; payload_len],
                    };
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if let RdState::Payload { pos, len, pkt } = &mut this.rd_state {
            let remaining = &mut pkt.as_mut_slice()[*pos..];
            let mut p = ReadBuf::new(remaining);
            match Pin::new(&mut this.inner).poll_read(cx, &mut p) {
                Poll::Ready(Ok(())) => {
                    let filled = p.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    *pos += filled;
                    if *pos < *len {
                        return Poll::Pending;
                    }
                    let plaintext = match this.crypto.decrypt_frame(pkt) {
                        Ok(pt) => pt,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    // 直接返回解密数据到用户缓冲区
                    let n = plaintext.len().min(buf.remaining());
                    buf.put_slice(&plaintext[..n]);
                    // 剩余部分存入内部缓冲区
                    if n < plaintext.len() {
                        this.read_buf = plaintext;
                        this.read_pos = n;
                    }
                    this.rd_state = RdState::Idle;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Pending
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let frame = match this.crypto.encrypt(buf) {
            Ok(f) => f,
            Err(e) => return Poll::Ready(Err(e)),
        };

        match Pin::new(&mut this.inner).poll_write(_cx, &frame) {
            Poll::Ready(Ok(n)) if n == frame.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "加密流部分写入",
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 使用 HKDF-SHA256 从共享秘密派生 32 字节密钥
///
/// HKDF 过程：extract(salt, ikm) → expand(prk, info, 32)
pub fn derive_key(shared_secret: &str) -> [u8; 32] {
    use hmac::Mac;

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    let salt = b"intrasweep-tunnel-v1";
    let mut extract = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC key 创建失败");
    extract.update(shared_secret.as_bytes());
    let prk = extract.finalize().into_bytes();

    let info = b"tunnel-encryption-key";
    let mut expand = <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC key 创建失败");
    expand.update(info);
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let key1 = derive_key("my-secret-password");
        let key2 = derive_key("my-secret-password");
        let key3 = derive_key("different-password");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_key("test-key");
        let layer = CryptoLayer::new(&key);

        let plaintext = b"Hello, encrypted tunnel!";
        let frame = layer.encrypt(plaintext).unwrap();

        let frame_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(frame_len, frame.len() - 4);
        assert!(frame_len >= 24 + 16);

        let decrypted = layer.decrypt_frame(&frame[4..]).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_empty() {
        let key = derive_key("test");
        let layer = CryptoLayer::new(&key);

        let frame = layer.encrypt(b"").unwrap();
        let decrypted = layer.decrypt_frame(&frame[4..]).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let key = derive_key("test");
        let layer = CryptoLayer::new(&key);

        let mut frame = layer.encrypt(b"secret").unwrap();
        if frame.len() > 30 {
            frame[30] ^= 0x01;
        }
        let result = layer.decrypt_frame(&frame[4..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let layer1 = CryptoLayer::new(&derive_key("key-a"));
        let layer2 = CryptoLayer::new(&derive_key("key-b"));

        let frame = layer1.encrypt(b"secret").unwrap();
        let result = layer2.decrypt_frame(&frame[4..]);
        assert!(result.is_err());
    }
}
