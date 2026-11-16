//! A strict bounded EC2 private COSE_Key decoder. No speculative PKCS#8 fallback.
use super::*;
pub fn decode_cose_private_key(bytes: &[u8]) -> Result<Es256Key, ExchangeError> {
    if bytes.len() > 256 {
        return Err(ExchangeError::new("passkey_cose_limit"));
    }
    let mut reader = Reader { bytes, position: 0 };
    let (major, count) = reader.head()?;
    if major != 5 || count != 6 {
        return Err(ExchangeError::new("passkey_cose_invalid"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let (mut x, mut y, mut d) = (None, None, None);
    for _ in 0..count {
        let key = reader.integer()?;
        if !seen.insert(key) {
            return Err(ExchangeError::new("passkey_cose_duplicate"));
        }
        match key {
            1 if reader.integer()? == 2 => {}
            3 if reader.integer()? == -7 => {}
            -1 if reader.integer()? == 1 => {}
            -2 => x = Some(reader.coordinate()?),
            -3 => y = Some(reader.coordinate()?),
            -4 => d = Some(reader.coordinate()?),
            _ => return Err(ExchangeError::new("passkey_cose_algorithm")),
        }
    }
    if reader.position != bytes.len() {
        return Err(ExchangeError::new("passkey_cose_invalid"));
    }
    let key = Es256Key::from_scalar(d.ok_or_else(|| ExchangeError::new("passkey_cose_invalid"))?)
        .map_err(PasskeyError::Crypto)?;
    let public = key.public_key();
    if Some(&public[1..33]) != x || Some(&public[33..65]) != y {
        return Err(ExchangeError::new("passkey_cose_public_key_invalid"));
    }
    Ok(key)
}
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn head(&mut self) -> Result<(u8, u64), ExchangeError> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| ExchangeError::new("passkey_cose_truncated"))?;
        self.position += 1;
        let number = match byte & 31 {
            0..=23 => u64::from(byte & 31),
            24 => {
                let value = *self
                    .bytes
                    .get(self.position)
                    .ok_or_else(|| ExchangeError::new("passkey_cose_truncated"))?;
                self.position += 1;
                if value < 24 {
                    return Err(ExchangeError::new("passkey_cose_encoding"));
                }
                u64::from(value)
            }
            _ => return Err(ExchangeError::new("passkey_cose_encoding")),
        };
        Ok((byte >> 5, number))
    }
    fn integer(&mut self) -> Result<i64, ExchangeError> {
        match self.head()? {
            (0, n) => Ok(n as i64),
            (1, n) => Ok(-1 - (n as i64)),
            _ => Err(ExchangeError::new("passkey_cose_integer")),
        }
    }
    fn coordinate(&mut self) -> Result<&'a [u8], ExchangeError> {
        if self.head()? != (2, 32) {
            return Err(ExchangeError::new("passkey_cose_coordinate"));
        }
        let value = self
            .bytes
            .get(self.position..self.position + 32)
            .ok_or_else(|| ExchangeError::new("passkey_cose_truncated"))?;
        self.position += 32;
        Ok(value)
    }
}
