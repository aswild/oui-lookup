use std::cmp;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MacAddress([u8; 6]);

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Generic error type used for indicating failure when parsing MAC addresses.
///
/// This is because clap's ValueParser magic for FromStr types requires that the type's Err type
/// implements std::error::Error, so we can't just use ()
#[derive(Debug)]
pub struct MacAddressParseError;

impl fmt::Display for MacAddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Invalid MAC address")
    }
}

impl std::error::Error for MacAddressParseError {}

impl std::str::FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(MacAddressParseError)
    }
}

impl MacAddress {
    /// Parse a MAC address string.
    ///
    /// If the address is truncated, then the last octets will be zero, e.g. `"aa:bb:cc"` parses to
    /// `aa:bb:cc:00:00:00`. Returns `None` on any parsing failure, including invalid characters,
    /// whitespace, or too many octets.
    pub fn parse(s: &str) -> Option<Self> {
        if !s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
            return None;
        }

        let mut octets = [0u8; 6];
        for (i, bs) in s.split(':').enumerate() {
            if i >= octets.len() {
                return None;
            }
            octets[i] = u8::from_str_radix(bs, 16).ok()?;
        }
        Some(Self(octets))
    }

    /// Get this MAC address in the LSB 48 bits of a u64.
    ///
    /// The upper 16 bits will always be zeroes.
    #[inline]
    pub fn to_u64(self) -> u64 {
        let mut v = [0u8; 8];
        v[2..8].copy_from_slice(&self.0);
        u64::from_be_bytes(v)
    }

    #[inline]
    pub fn from_u64(val: u64) -> Self {
        let b8 = val.to_be_bytes();
        let mut b6 = [0u8; 6];
        b6.copy_from_slice(&b8[2..8]);
        Self(b6)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MacPrefix {
    /// Packed MAC address and prefix length.
    ///
    /// Bits 63..56 - prefix length (in bits, always <= 48)
    /// Bits 48..55 - unused
    /// Bits 47..40 - mac[0]
    /// Bits 32..39 - mac[1]
    /// ...
    /// Bits 7..0   - mac[5]
    val: u64,
}

impl fmt::Debug for MacPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.prefix_len() == 0 {
            // unusual special case, just display the MAC normally
            return fmt::Debug::fmt(&self.mac(), f);
        }

        // ceil(prefix_len / 8)
        let count = ((self.prefix_len() - 1) / 8) + 1;
        let o = self.mac().0;
        for i in 0..count {
            if i != 0 {
                f.write_str(":")?;
            }
            write!(f, "{:02x}", o[i as usize])?;
        }
        write!(f, "/{}", self.prefix_len())?;
        Ok(())
    }
}

impl fmt::Display for MacPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl cmp::Ord for MacPrefix {
    #[inline]
    fn cmp(&self, rhs: &MacPrefix) -> cmp::Ordering {
        self.mac().cmp(&rhs.mac())
    }
}

impl cmp::PartialOrd for MacPrefix {
    #[inline]
    fn partial_cmp(&self, rhs: &MacPrefix) -> Option<cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}

impl MacPrefix {
    /// Get a mask for the given prefix length
    fn mask(prefix_len: u8) -> u64 {
        debug_assert!(prefix_len <= 48);
        ((1u64 << prefix_len) - 1) << (48 - prefix_len)
    }

    /// Parse a MAC prefix string.
    ///
    /// One to six colon-separated hex octets, optionally followed by a `/` and a prefix length. If
    /// the prefix length is omitted, it's assumed to be 24 bits (3 octets).
    pub fn parse(s: &str) -> Option<Self> {
        let (mac, prefix_len) = match s.split_once('/') {
            Some((m, p)) => (m, p.parse::<u8>().ok()?),
            None => (s, 24),
        };
        let mac = MacAddress::parse(mac)?;
        Some(Self::from_parts(mac, prefix_len))
    }

    pub fn from_parts(mac: MacAddress, prefix_len: u8) -> Self {
        let val = ((prefix_len as u64) << 56) | (mac.to_u64() & Self::mask(prefix_len));
        Self { val }
    }

    /// Get the MAC address portion of this prefix
    #[inline]
    pub fn mac(self) -> MacAddress {
        MacAddress::from_u64(self.val & 0x0000_ffff_ffff_ffff)
    }

    /// Get the prefix length of this MAC prefix
    #[inline]
    pub fn prefix_len(self) -> u8 {
        (self.val >> 56) as u8
    }

    /// Does this prefix match some MAC address?
    pub fn matches(self, mac: MacAddress) -> bool {
        let mask = Self::mask(self.prefix_len());
        (mac.to_u64() & mask) == (self.val & mask)
    }
}

#[derive(Debug)]
pub struct Oui {
    pub mac_prefix: MacPrefix,
    #[allow(unused)]
    pub short_name: String,
    pub long_name: String,
}

impl Oui {
    /// Parse a single line of the wireshark `manuf` database.
    pub fn from_manuf(s: &str) -> Option<Self> {
        let s = s.trim_start();
        if s.starts_with('#') {
            return None;
        }

        let (mac_s, s) = s.split_at(s.find(|c: char| c.is_whitespace())?);
        let mac_prefix = MacPrefix::parse(mac_s)?;

        let (_, s) = s.split_at(s.find(|c: char| !c.is_whitespace())?);
        let (short, s) = s.split_at(s.find(|c: char| c.is_whitespace())?);
        let (_, long) = s.split_at(s.find(|c: char| !c.is_whitespace())?);

        let short_name = short.to_string();
        let long_name = long.to_string();
        Some(Self {
            mac_prefix,
            short_name,
            long_name,
        })
    }

    #[inline]
    pub fn mac(&self) -> MacAddress {
        self.mac_prefix.mac()
    }

    #[allow(unused)]
    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.mac_prefix.prefix_len()
    }
}

impl cmp::PartialEq for Oui {
    fn eq(&self, rhs: &Oui) -> bool {
        self.mac_prefix == rhs.mac_prefix
    }
}

impl cmp::Eq for Oui {}

impl cmp::Ord for Oui {
    #[inline]
    fn cmp(&self, rhs: &Oui) -> cmp::Ordering {
        self.mac_prefix.cmp(&rhs.mac_prefix)
    }
}

impl cmp::PartialOrd for Oui {
    #[inline]
    fn partial_cmp(&self, rhs: &Oui) -> Option<cmp::Ordering> {
        Some(self.cmp(rhs))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse() {
        let o = Oui::from_manuf("00:50:F1           Maxlinear       Maxlinear, Inc").unwrap();
        assert_eq!(&o.mac().0, b"\x00\x50\xf1\x00\x00\x00");
        assert_eq!(o.prefix_len(), 24);
        assert_eq!(o.short_name, "Maxlinear");
        assert_eq!(o.long_name, "Maxlinear, Inc");

        let o = Oui::from_manuf("00:55:DA:50/28     Nanoleaf        Nanoleaf").unwrap();
        assert_eq!(&o.mac().0, b"\x00\x55\xda\x50\x00\x00");
        assert_eq!(o.prefix_len(), 28);
        assert_eq!(o.short_name, "Nanoleaf");
        assert_eq!(o.long_name, "Nanoleaf");

        assert!(Oui::from_manuf("# foo bar").is_none());
    }

    #[test]
    fn test_matches() {
        let prefix = MacPrefix::parse("01:02:03").unwrap();
        assert!(prefix.matches(MacAddress::parse("01:02:03:04:05:06").unwrap()));
        assert!(!prefix.matches(MacAddress::parse("01:02:33:00:00:00").unwrap()));

        let prefix = MacPrefix::parse("00:1B:C5:00:10/36").unwrap();
        assert!(prefix.matches(MacAddress::parse("00:1b:c5:00:10:aa").unwrap()));
        assert!(prefix.matches(MacAddress::parse("00:1b:c5:00:11:aa").unwrap()));
        assert!(!prefix.matches(MacAddress::parse("00:1b:c5:00:20:bb").unwrap()));
    }
}
