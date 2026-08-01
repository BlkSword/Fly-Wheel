//! 敏感字符串混淆模块
//!
//! 编译时 XOR 编码，运行时解码，避免静态查杀

/// XOR 解码
#[inline(always)]
pub fn xor_decode(encoded: &[u8], key: u8) -> String {
    let decoded: Vec<u8> = encoded.iter().map(|&b| b ^ key).collect();
    String::from_utf8(decoded).unwrap_or_default()
}

/// 混淆后的敏感字符串
pub mod sensitive {
    use super::xor_decode;

    const KEY: u8 = 0x5A;

    pub fn crack_label() -> String {
        xor_decode(
            &[
                0xBF, 0xF5, 0xDC, 0xBD, 0xFA, 0xDB, 0xBD, 0xD2, 0xDC, 0xBD, 0xFA, 0xEE,
            ],
            KEY,
        )
    }

    pub fn tunnel_label() -> String {
        xor_decode(&[0xB3, 0xC0, 0xFD, 0xB3, 0xDB, 0xC9], KEY)
    }

    pub fn penetrate_label() -> String {
        xor_decode(&[0xBD, 0xF3, 0xE5, 0xB3, 0xDA, 0xD5], KEY)
    }

    pub fn sweep_full_label() -> String {
        xor_decode(
            &[
                0xBF, 0xDC, 0xDF, 0xBD, 0xE7, 0xCB, 0xBC, 0xE2, 0xCD, 0xB3, 0xDA, 0xD5, 0xB2, 0xE4,
                0xDF, 0xBF, 0xD0, 0xF3, 0xBF, 0xED, 0xFF, 0xBF, 0xDF, 0xED,
            ],
            KEY,
        )
    }

    pub fn credential_label() -> String {
        xor_decode(&[0xBF, 0xDD, 0xF7, 0xBC, 0xD7, 0xF4], KEY)
    }

    pub fn forward_tunnel_label() -> String {
        xor_decode(
            &[
                0xBC, 0xF7, 0xF9, 0xBF, 0xCA, 0xCB, 0xB3, 0xC0, 0xFD, 0xB3, 0xDB, 0xC9,
            ],
            KEY,
        )
    }

    pub fn reverse_tunnel_label() -> String {
        xor_decode(
            &[
                0xBF, 0xD5, 0xD7, 0xBF, 0xCA, 0xCB, 0xB3, 0xC0, 0xFD, 0xB3, 0xDB, 0xC9,
            ],
            KEY,
        )
    }

    pub fn socks5_proxy_label() -> String {
        xor_decode(
            &[
                0x09, 0x15, 0x19, 0x11, 0x09, 0x6F, 0xBE, 0xE1, 0xF9, 0xBD, 0xCA, 0xDC,
            ],
            KEY,
        )
    }

    pub fn chain_tunnel_label() -> String {
        xor_decode(
            &[
                0xB3, 0xC9, 0xE4, 0xBF, 0xE6, 0xD5, 0xB3, 0xC0, 0xFD, 0xB3, 0xDB, 0xC9,
            ],
            KEY,
        )
    }

    pub fn crack_success_label() -> String {
        xor_decode(
            &[
                0xBD, 0xD2, 0xDC, 0xBD, 0xFA, 0xEE, 0xBC, 0xD2, 0xCA, 0xBF, 0xD0, 0xC5,
            ],
            KEY,
        )
    }

    pub fn crack_failed_label() -> String {
        xor_decode(
            &[
                0xBD, 0xD2, 0xDC, 0xBD, 0xFA, 0xEE, 0xBF, 0xFE, 0xEB, 0xB2, 0xEE, 0xFF,
            ],
            KEY,
        )
    }

    pub fn intranet_sweep_label() -> String {
        xor_decode(
            &[
                0xBF, 0xDC, 0xDF, 0xBD, 0xE7, 0xCB, 0xBC, 0xE2, 0xCD, 0xB3, 0xDA, 0xD5,
            ],
            KEY,
        )
    }

    pub fn vuln_label() -> String {
        xor_decode(
            &[
                0xBC, 0xE6, 0xD5, 0xBC, 0xEE, 0xC4, 0xBC, 0xD3, 0xF1, 0xBC, 0xD5, 0xD5,
            ],
            KEY,
        )
    }

    pub fn privesc_label() -> String {
        xor_decode(
            &[
                0xBC, 0xD5, 0xCA, 0xBC, 0xC7, 0xD9, 0xBC, 0xF9, 0xDA, 0xBC, 0xEF, 0xD1,
            ],
            KEY,
        )
    }

    pub fn banner_label() -> String {
        xor_decode(
            &[
                0x13, 0x34, 0x2E, 0x28, 0x3B, 0x09, 0x2D, 0x3F, 0x3F, 0x2A, 0x7A, 0x77, 0x7A, 0xBF,
                0xDC, 0xDF, 0xBD, 0xE7, 0xCB, 0xBC, 0xE2, 0xCD, 0xB3, 0xDA, 0xD5, 0xB2, 0xE4, 0xDF,
                0xBF, 0xD0, 0xF3, 0xBF, 0xED, 0xFF, 0xBF, 0xDF, 0xED, 0x7A, 0x2C, 0x6A, 0x74, 0x6E,
                0x74, 0x6A,
            ],
            KEY,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::sensitive;

    #[test]
    fn test_crack_label() {
        assert_eq!(sensitive::crack_label(), "密码爆破");
    }

    #[test]
    fn test_tunnel_label() {
        assert_eq!(sensitive::tunnel_label(), "隧道");
    }

    #[test]
    fn test_penetrate_label() {
        assert_eq!(sensitive::penetrate_label(), "穿透");
    }

    #[test]
    fn test_sweep_full_label() {
        assert_eq!(sensitive::sweep_full_label(), "内网渗透辅助工具");
    }

    #[test]
    fn test_credential_label() {
        assert_eq!(sensitive::credential_label(), "凭据");
    }

    #[test]
    fn test_forward_tunnel_label() {
        assert_eq!(sensitive::forward_tunnel_label(), "正向隧道");
    }

    #[test]
    fn test_reverse_tunnel_label() {
        assert_eq!(sensitive::reverse_tunnel_label(), "反向隧道");
    }

    #[test]
    fn test_socks5_proxy_label() {
        assert_eq!(sensitive::socks5_proxy_label(), "SOCKS5代理");
    }

    #[test]
    fn test_chain_tunnel_label() {
        assert_eq!(sensitive::chain_tunnel_label(), "链式隧道");
    }

    #[test]
    fn test_crack_success_label() {
        assert_eq!(sensitive::crack_success_label(), "爆破成功");
    }

    #[test]
    fn test_crack_failed_label() {
        assert_eq!(sensitive::crack_failed_label(), "爆破失败");
    }

    #[test]
    fn test_intranet_sweep_label() {
        assert_eq!(sensitive::intranet_sweep_label(), "内网渗透");
    }

    #[test]
    fn test_vuln_label() {
        assert_eq!(sensitive::vuln_label(), "漏洞扫描");
    }

    #[test]
    fn test_privesc_label() {
        assert_eq!(sensitive::privesc_label(), "提权检测");
    }

    #[test]
    fn test_banner_label() {
        assert_eq!(
            sensitive::banner_label(),
            "IntraSweep - 内网渗透辅助工具 v0.4.0"
        );
    }
}
