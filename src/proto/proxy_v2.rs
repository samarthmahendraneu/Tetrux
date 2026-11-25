//! Spec-compliant HAProxy PROXY Protocol v2 binary encoder & decoder (0 heap allocations!).
//! Preserves original client IP & port across L4 TCP proxies for Tier-0 backends.

use crate::sys::EndpointV4;
use std::net::Ipv6Addr;

/// Official 12-byte PROXY Protocol v2 binary signature.
pub const PROXY_V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Version 2 (0x20) | PROXY command (0x01)
const VER_CMD_PROXY: u8 = 0x21;
/// AF_INET (0x10) | STREAM (0x01)
const FAM_TCP_IPV4: u8 = 0x11;
/// AF_INET6 (0x20) | STREAM (0x01)
const FAM_TCP_IPV6: u8 = 0x21;

/// Total size of an IPv4 TCP PROXY v2 header: 16B header + 12B addresses = 28 bytes.
pub const PROXY_V2_IPV4_LEN: usize = 28;
/// Total size of an IPv6 TCP PROXY v2 header: 16B header + 36B addresses = 52 bytes.
pub const PROXY_V2_IPV6_LEN: usize = 52;

/// Encode a PROXY Protocol v2 header for an IPv4 TCP connection onto the stack (0 allocs).
#[inline]
pub fn encode_tcp_v4(src: EndpointV4, dst: EndpointV4) -> [u8; PROXY_V2_IPV4_LEN] {
    let mut buf = [0u8; PROXY_V2_IPV4_LEN];
    buf[0..12].copy_from_slice(&PROXY_V2_SIG);
    buf[12] = VER_CMD_PROXY;
    buf[13] = FAM_TCP_IPV4;
    buf[14..16].copy_from_slice(&12u16.to_be_bytes());
    buf[16..20].copy_from_slice(&src.ip.to_be_bytes());
    buf[20..24].copy_from_slice(&dst.ip.to_be_bytes());
    buf[24..26].copy_from_slice(&src.port.to_be_bytes());
    buf[26..28].copy_from_slice(&dst.port.to_be_bytes());
    buf
}

/// Encode a PROXY Protocol v2 header for an IPv6 TCP connection onto the stack (0 allocs).
#[inline]
pub fn encode_tcp_v6(
    src_ip: Ipv6Addr,
    src_port: u16,
    dst_ip: Ipv6Addr,
    dst_port: u16,
) -> [u8; PROXY_V2_IPV6_LEN] {
    let mut buf = [0u8; PROXY_V2_IPV6_LEN];
    buf[0..12].copy_from_slice(&PROXY_V2_SIG);
    buf[12] = VER_CMD_PROXY;
    buf[13] = FAM_TCP_IPV6;
    buf[14..16].copy_from_slice(&36u16.to_be_bytes());
    buf[16..32].copy_from_slice(&src_ip.octets());
    buf[32..48].copy_from_slice(&dst_ip.octets());
    buf[48..50].copy_from_slice(&src_port.to_be_bytes());
    buf[50..52].copy_from_slice(&dst_port.to_be_bytes());
    buf
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedProxyV2 {
    TcpV4 {
        src: EndpointV4,
        dst: EndpointV4,
        header_len: usize,
    },
    TcpV6 {
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
        header_len: usize,
    },
}

/// Decode a PROXY Protocol v2 header from a byte slice (returns `None` if incomplete/invalid).
pub fn decode_v2(buf: &[u8]) -> Option<DecodedProxyV2> {
    if buf.len() < 16 || buf[0..12] != PROXY_V2_SIG {
        return None;
    }
    if (buf[12] & 0xF0) != 0x20 || (buf[12] & 0x0F) != 0x01 {
        return None;
    }
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total_len = 16 + addr_len;
    if buf.len() < total_len {
        return None;
    }
    match buf[13] {
        FAM_TCP_IPV4 if addr_len >= 12 => {
            let src_ip = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
            let dst_ip = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
            let src_port = u16::from_be_bytes([buf[24], buf[25]]);
            let dst_port = u16::from_be_bytes([buf[26], buf[27]]);
            Some(DecodedProxyV2::TcpV4 {
                src: EndpointV4::new(src_ip, src_port),
                dst: EndpointV4::new(dst_ip, dst_port),
                header_len: total_len,
            })
        }
        FAM_TCP_IPV6 if addr_len >= 36 => {
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&buf[16..32]);
            d.copy_from_slice(&buf[32..48]);
            let src_port = u16::from_be_bytes([buf[48], buf[49]]);
            let dst_port = u16::from_be_bytes([buf[50], buf[51]]);
            Some(DecodedProxyV2::TcpV6 {
                src_ip: Ipv6Addr::from(s),
                src_port,
                dst_ip: Ipv6Addr::from(d),
                dst_port,
                header_len: total_len,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_v2_ipv4_and_ipv6_roundtrip() {
        let src = EndpointV4::from_octets(203, 0, 113, 42, 54321);
        let dst = EndpointV4::from_octets(198, 51, 100, 1, 443);
        let hdr = encode_tcp_v4(src, dst);
        assert_eq!(hdr.len(), PROXY_V2_IPV4_LEN);
        assert_eq!(
            decode_v2(&hdr),
            Some(DecodedProxyV2::TcpV4 {
                src,
                dst,
                header_len: 28
            })
        );

        let s6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let d6: Ipv6Addr = "2001:db8::99".parse().unwrap();
        let hdr6 = encode_tcp_v6(s6, 12345, d6, 8443);
        assert_eq!(hdr6.len(), PROXY_V2_IPV6_LEN);
        assert_eq!(
            decode_v2(&hdr6),
            Some(DecodedProxyV2::TcpV6 {
                src_ip: s6,
                src_port: 12345,
                dst_ip: d6,
                dst_port: 8443,
                header_len: 52
            })
        );
        assert!(decode_v2(b"not proxy v2").is_none());
    }
}
