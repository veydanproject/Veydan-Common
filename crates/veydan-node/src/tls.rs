//! A node's own TLS: the certificate chain it shows and the key under it.
//! (What a caller needs is in `pin`; how a bridge and a hub answer and call
//! each other is in `vlink-proto`.)

use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};

use crate::error::Error;
use crate::id::NodeId;
use crate::pin::{self, tls};

pub use crate::pin::server_name;

/// A certificate chain with the key of its first certificate, as read
/// from PEM files or just made. A node's chain is two certificates: the
/// TLS one, and the one carrying the node's key that signed it (`id`).
/// A hub's is one, signed by the VLink root.
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Error> {
        use rustls::pki_types::pem::PemObject;
        let chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(tls)?;
        if chain.is_empty() {
            return Err(Error::Tls("no certificate in the file".into()));
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(tls)?;
        Ok(Self { chain, key })
    }

    /// The id a node with this chain has, held to the rule every caller
    /// holds it to (`NodeId::of_chain`) as of now: a chain a client
    /// would refuse has no id, and a node does not start on it.
    pub fn node_id(&self) -> Result<NodeId, Error> {
        let now = UnixTime::now();
        NodeId::of_chain(&self.chain[0], &self.chain[1..], now, pin::provider().signature_verification_algorithms.all)
    }
}

/// One certificate out of a PEM text: a root.
pub fn cert_from_pem(pem: &str) -> Result<CertificateDer<'static>, Error> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes()).map_err(tls)
}

/// `notAfter` of a certificate (DER), unix seconds; `None` when it cannot
/// be read. For a node's own chain and a hub's own certificate, to tell
/// when either has to be issued again.
pub fn not_after(der: &[u8]) -> Option<u64> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    // [0] version, when there.
    if rest.first() == Some(&0xA0) {
        rest = tlv(rest)?.2;
    }
    let (_, _serial, rest) = tlv(rest)?;
    let (_, _algorithm, rest) = tlv(rest)?;
    let (_, _issuer, rest) = tlv(rest)?;
    let (_, validity, _) = tlv(rest)?;
    let (_, _not_before, after) = tlv(validity)?;
    let (tag, text, _) = tlv(after)?;
    time_of(tag, text)
}

/// One TLV of DER: `(tag, content, rest)`.
fn tlv(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *der.first()?;
    let first = *der.get(1)?;
    let (len, at) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in der.get(2..2 + n)? {
            len = (len << 8) | usize::from(*b);
        }
        (len, 2 + n)
    };
    let end = at.checked_add(len)?;
    Some((tag, der.get(at..end)?, &der[end..]))
}

/// UTCTime (0x17, `YYMMDDHHMMSSZ`) or GeneralizedTime (0x18,
/// `YYYYMMDDHHMMSSZ`) as unix seconds.
fn time_of(tag: u8, text: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if text.len() == 12 => {
            let yy: i64 = text[..2].parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &text[2..])
        }
        0x18 if text.len() == 14 => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    let n = |i: usize| rest.get(i..i + 2).and_then(|s| s.parse::<i64>().ok());
    let (month, day, hour, minute, second) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days from the civil date (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dates_of_a_certificate_are_read() {
        // 2026-01-01 and 2056-01-01: UTCTime and GeneralizedTime.
        assert_eq!(not_after(&[]), None);
        assert_eq!(not_after(&[0x30, 0x03, 0x30, 0x01]), None);
        assert_eq!(time_of(0x17, b"260101000000Z"), Some(1_767_225_600));
        assert_eq!(time_of(0x18, b"20560101000000Z"), Some(2_713_910_400));
        assert_eq!(time_of(0x18, b"20561301000000Z"), None);
    }
}
