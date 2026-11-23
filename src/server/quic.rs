//! Read only the client's Initial encryption level (RFC 9001 and RFC 9369).
use ring::{
    aead::{self, quic::HeaderProtectionKey},
    hkdf,
};

const MAX_HELLO: usize = 16 * 1024;
const MAX_PACKETS: u8 = 16;
const V1: u32 = 1;
const V2: u32 = 0x6b3343cf;
const V1_SALT: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const V2_SALT: &[u8] = &[
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

fn take<'a>(input: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    input.split_off(..len)
}
fn varint(input: &mut &[u8]) -> Option<u64> {
    let bytes = take(input, 1 << (input.first()? >> 6))?;
    Some(
        bytes[1..]
            .iter()
            .fold(u64::from(bytes[0] & 63), |n, b| (n << 8) | u64::from(*b)),
    )
}
fn length(input: &mut &[u8]) -> Option<usize> {
    usize::try_from(varint(input)?).ok()
}

struct Size(usize);
impl hkdf::KeyType for Size {
    fn len(&self) -> usize {
        self.0
    }
}
fn expand<const N: usize>(secret: &hkdf::Prk, label: &[u8]) -> Option<[u8; N]> {
    let mut out = [0; N];
    secret
        .expand(&[&[0, N as u8, label.len() as u8], label, &[0]], Size(N))
        .ok()?
        .fill(&mut out)
        .ok()?;
    Some(out)
}

struct InitialKeys {
    hp: HeaderProtectionKey,
    key: aead::LessSafeKey,
    iv: [u8; 12],
}
impl InitialKeys {
    fn new(version: u32, dcid: &[u8]) -> Option<Self> {
        let (salt, key, iv, hp): (&[u8], &[u8], &[u8], &[u8]) = match version {
            V1 => (
                V1_SALT,
                b"tls13 quic key",
                b"tls13 quic iv",
                b"tls13 quic hp",
            ),
            V2 => (
                V2_SALT,
                b"tls13 quicv2 key",
                b"tls13 quicv2 iv",
                b"tls13 quicv2 hp",
            ),
            _ => return None,
        };
        let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
        let client = hkdf::Prk::new_less_safe(
            hkdf::HKDF_SHA256,
            &expand::<32>(&initial, b"tls13 client in")?,
        );
        Some(Self {
            hp: HeaderProtectionKey::new(&aead::quic::AES_128, &expand::<16>(&client, hp)?).ok()?,
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_128_GCM, &expand::<16>(&client, key)?).ok()?,
            ),
            iv: expand(&client, iv)?,
        })
    }
    fn open(&self, packet: &[u8], offset: usize, expected: u64) -> Option<(u64, Vec<u8>)> {
        let mask = self
            .hp
            .new_mask(packet.get(offset + 4..offset + 20)?)
            .ok()?;
        let first = packet[0] ^ (mask[0] & 15);
        if first & 12 != 0 {
            return None;
        }
        let width = usize::from(first & 3) + 1;
        let (header, body) = packet.split_at_checked(offset + width)?;
        let mut aad = header.to_vec();
        aad[0] = first;
        let mut truncated = 0;
        for (b, m) in aad[offset..].iter_mut().zip(&mask[1..]) {
            *b ^= m;
            truncated = truncated << 8 | u64::from(*b);
        }
        let window = 1u64 << (8 * width);
        let half = window / 2;
        let mut number = (expected & !(window - 1)) | truncated;
        if number + half <= expected {
            number += window;
        } else if number > expected + half && number >= window {
            number -= window;
        }
        let mut nonce = self.iv;
        for (a, b) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *a ^= b;
        }
        let mut payload = body.to_vec();
        let len = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut payload,
            )
            .ok()?
            .len();
        payload.truncate(len);
        Some((number, payload))
    }
}

#[derive(Default)]
struct CryptoStream {
    bytes: Vec<u8>,
    present: Vec<u8>,
    prefix: usize,
}
impl CryptoStream {
    fn insert(&mut self, offset: usize, data: &[u8]) -> Option<()> {
        let end = offset.checked_add(data.len())?;
        if end > MAX_HELLO {
            return None;
        }
        if end > self.bytes.len() {
            self.bytes.resize(end, 0);
            self.present.resize(end.div_ceil(8), 0);
        }
        for (i, &b) in (offset..end).zip(data) {
            let bit = 1 << (i % 8);
            if self.present[i / 8] & bit != 0 && self.bytes[i] != b {
                return None;
            }
            self.bytes[i] = b;
            self.present[i / 8] |= bit;
        }
        while self.prefix < self.bytes.len()
            && self.present[self.prefix / 8] & (1 << (self.prefix % 8)) != 0
        {
            self.prefix += 1;
        }
        Some(())
    }
    fn frames(&mut self, mut input: &[u8]) -> Option<()> {
        while !input.is_empty() {
            match varint(&mut input)? {
                0 | 1 => {} // PADDING, PING
                ty @ (2 | 3) => {
                    // ACK, ACK_ECN
                    varint(&mut input)?;
                    varint(&mut input)?;
                    let ranges = varint(&mut input)?;
                    varint(&mut input)?;
                    for _ in 0..ranges {
                        varint(&mut input)?;
                        varint(&mut input)?;
                    }
                    if ty == 3 {
                        for _ in 0..3 {
                            varint(&mut input)?;
                        }
                    }
                }
                6 => {
                    let offset = length(&mut input)?;
                    let len = length(&mut input)?;
                    self.insert(offset, take(&mut input, len)?)?;
                }
                _ => return None,
            }
        }
        Some(())
    }
    fn hello(&self) -> Option<&[u8]> {
        let mut data = self.bytes.get(..self.prefix)?;
        let header = take(&mut data, 4)?;
        if header[0] != 1 {
            return None;
        }
        let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
        take(&mut data, length)
    }
}

#[derive(Default)]
pub(super) struct Probe {
    attempts: u8,
    // Retries can replace the destination CID and reset the Initial keys.
    connection: Option<(u32, Vec<u8>, Box<InitialKeys>)>,
    expected: u64,
    crypto: CryptoStream,
}
impl Probe {
    pub fn finished(&self) -> bool {
        self.attempts >= MAX_PACKETS
    }
    pub fn inspect(&mut self, datagram: &[u8]) -> Option<String> {
        if self.finished() {
            return None;
        }
        self.attempts += 1;
        if datagram.len() < 1200 || datagram[0] & 0xc0 != 0xc0 {
            if self.connection.is_none() {
                self.attempts = MAX_PACKETS;
            }
            return None;
        }
        let mut wire = datagram;
        while let Some((first, mut fields)) = wire.split_first() {
            if first & 0xc0 != 0xc0 {
                return None;
            }
            let version = u32::from_be_bytes(take(&mut fields, 4)?.try_into().ok()?);
            if !matches!((version, (first >> 4) & 3), (V1, 0) | (V2, 1)) {
                return None;
            }
            let dcid_len = usize::from(*take(&mut fields, 1)?.first()?);
            if dcid_len > 20 {
                return None;
            }
            let dcid = take(&mut fields, dcid_len)?;
            let scid_len = usize::from(*take(&mut fields, 1)?.first()?);
            if scid_len > 20 {
                return None;
            }
            take(&mut fields, scid_len)?;
            let token = length(&mut fields)?;
            take(&mut fields, token)?;
            let len = length(&mut fields)?;
            let offset = wire.len() - fields.len();
            if len > MAX_HELLO {
                return None;
            }
            let (packet, rest) = wire.split_at_checked(offset.checked_add(len)?)?;
            let changed = self
                .connection
                .as_ref()
                .is_none_or(|(v, c, _)| *v != version || c != dcid);
            let fresh = if changed {
                Some(Box::new(InitialKeys::new(version, dcid)?))
            } else {
                None
            };
            let keys = fresh
                .as_ref()
                .or_else(|| self.connection.as_ref().map(|(_, _, k)| k))?;
            let (pn, payload) =
                keys.open(packet, offset, if changed { 0 } else { self.expected })?;
            if let Some(keys) = fresh {
                self.connection = Some((version, dcid.to_vec(), keys));
                self.expected = 0;
                self.crypto = CryptoStream::default();
            }
            self.expected = self.expected.max(pn + 1);
            self.crypto.frames(&payload)?;
            if let Some(hello) = self.crypto.hello() {
                self.attempts = MAX_PACKETS;
                return super::sniff::sni(hello);
            }
            wire = rest;
            if !wire.is_empty() {
                if self.finished() {
                    break;
                }
                self.attempts += 1;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_initials_and_tag_validation() {
        // RFC 9001 A.2 and RFC 9369 A.2, including header protection and packet number.
        for packet in [
            include_bytes!("../../test/quic/rfc9001-client-initial.bin"),
            include_bytes!("../../test/quic/rfc9369-client-initial.bin"),
        ] {
            let mut bad = packet.to_vec();
            bad[37] ^= 1;
            let mut probe = Probe::default();
            assert_eq!(probe.inspect(&bad), None);
            assert_eq!(probe.inspect(packet).as_deref(), Some("example.com"));
            assert!(probe.finished());
        }
    }
    #[test]
    fn reordered_crypto_ranges_are_bounded() {
        let mut data = CryptoStream::default();
        data.insert(4, b"hi").unwrap();
        assert!(data.hello().is_none());
        data.insert(0, &[1, 0, 0, 2]).unwrap();
        data.insert(3, &[2, b'h']).unwrap();
        assert_eq!(data.hello(), Some(b"hi".as_slice()));
        assert!(data.insert(4, b"x").is_none());
        assert!(data.insert(MAX_HELLO, b"x").is_none());
    }
}
