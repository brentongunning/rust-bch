use address::AddressType;
use network::Network;
use util::{Error, Result};

// Cashaddr lookup tables to convert a 5-bit number to an ascii character and back
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

// Flags for the version byte
#[allow(dead_code)]
mod version_byte_flags {
    pub const TYPE_MASK: u8 = 0x78;
    pub const TYPE_P2PKH: u8 = 0x00;
    pub const TYPE_P2SH: u8 = 0x08;

    pub const SIZE_MASK: u8 = 0x07;
    pub const SIZE_160: u8 = 0x00;
    pub const SIZE_192: u8 = 0x01;
    pub const SIZE_224: u8 = 0x02;
    pub const SIZE_256: u8 = 0x03;
    pub const SIZE_320: u8 = 0x04;
    pub const SIZE_384: u8 = 0x05;
    pub const SIZE_448: u8 = 0x06;
    pub const SIZE_512: u8 = 0x07;
}

/// Converts a public key hash to its cashaddr address
pub fn cashaddr_encode(data: &[u8], addr_type: AddressType, network: Network) -> Result<String> {
    let mut version_byte = match addr_type {
        AddressType::P2PKH => version_byte_flags::TYPE_P2PKH,
        AddressType::P2SH => version_byte_flags::TYPE_P2SH,
    };
    let size_flag = match data.len() {
        20 => version_byte_flags::SIZE_160,
        24 => version_byte_flags::SIZE_192,
        28 => version_byte_flags::SIZE_224,
        32 => version_byte_flags::SIZE_256,
        40 => version_byte_flags::SIZE_320,
        48 => version_byte_flags::SIZE_384,
        56 => version_byte_flags::SIZE_448,
        64 => version_byte_flags::SIZE_512,
        _ => {
            let msg = format!("Size is not allowed: {}", data.len());
            return Err(Error::BadArgument(msg));
        }
    };
    version_byte = version_byte | size_flag;
    encode_with_version_byte(data, version_byte, network)
}

/// Decodes a cashaddr address to a public key hash
pub fn cashaddr_decode(input: &str, network: Network) -> Result<(Vec<u8>, AddressType)> {
    // Do some sanity checks on the string
    let mut upper = false;
    let mut lower = false;
    for c in input.chars() {
        if c.is_lowercase() {
            if upper {
                let msg = "Address cannot contain both upper and lower case".to_string();
                return Err(Error::BadData(msg));
            }
            lower = true;
        } else if c.is_uppercase() {
            if lower {
                let msg = "Address cannot contain both upper and lower case".to_string();
                return Err(Error::BadData(msg));
            }
            upper = true;
        }
    }

    // Split the prefix from the rest
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() < 2 {
        return Err(Error::BadData("No prefix separator ':'".to_string()));
    }
    if parts.len() > 2 {
        return Err(Error::BadData("Too many prefixes".to_string()));
    }
    if parts[0].to_lowercase() != network.cashaddr_prefix() {
        let msg = format!("Unexpected prefix: {}", parts[0]);
        return Err(Error::BadData(msg));
    }

    // Verify the checksum
    let mut checksum_input = Vec::with_capacity(input.len());
    for c in network.cashaddr_prefix().chars() {
        checksum_input.push((c as u8) & 31);
    }
    checksum_input.push(0); // 0 for prefix
    for c in parts[1].chars() {
        if c as u32 > 127 {
            let msg = format!("Address contains non-ascii characters: {}", c);
            return Err(Error::BadData(msg));
        }
        let d = CHARSET_REV[c as usize];
        if d == -1 {
            let msg = format!("Address contains invalid cashaddr characters: {}", c);
            return Err(Error::BadData(msg));
        }
        checksum_input.push(d as u8);
    }
    let checksum = polymod(&checksum_input);
    if checksum != 0 {
        return Err(Error::BadData("Nonzero checksum".to_string()));
    }

    // Extract the payload squeezed between the prefix and checksum in the checksum_input
    let lower = parts[0].len() + 1;
    let upper = checksum_input.len() - 8;
    let payload = convert_bits(&checksum_input[lower..upper], 5, 8, false);

    // Verify the version byte
    let version = payload[0];
    let encoded_data = payload[1..].to_vec();

    let version_size = version & version_byte_flags::SIZE_MASK;
    if (version_size == version_byte_flags::SIZE_160 && encoded_data.len() != 20)
        || (version_size == version_byte_flags::SIZE_192 && encoded_data.len() != 24)
        || (version_size == version_byte_flags::SIZE_224 && encoded_data.len() != 28)
        || (version_size == version_byte_flags::SIZE_256 && encoded_data.len() != 32)
        || (version_size == version_byte_flags::SIZE_320 && encoded_data.len() != 40)
        || (version_size == version_byte_flags::SIZE_384 && encoded_data.len() != 48)
        || (version_size == version_byte_flags::SIZE_448 && encoded_data.len() != 56)
        || (version_size == version_byte_flags::SIZE_512 && encoded_data.len() != 64)
    {
        let msg = format!("Wrong size: {}", encoded_data.len());
        return Err(Error::BadData(msg));
    }

    // Extract the address type and return
    let version_type = version & version_byte_flags::TYPE_MASK;
    let addr_type = if version_type == version_byte_flags::TYPE_P2PKH {
        AddressType::P2PKH
    } else if version_type == version_byte_flags::TYPE_P2SH {
        AddressType::P2SH
    } else {
        let msg = format!("Invalid type in version byte: {}", version);
        return Err(Error::BadData(msg));
    };

    Ok((encoded_data, addr_type))
}

fn encode_with_version_byte(data: &[u8], version_byte: u8, network: Network) -> Result<String> {
    // Generate the payload used both for calculating the checkum and the resulting address
    // It consists of a single version byte and the data to encode (pubkey hash) in 5-bit chunks
    let mut payload = Vec::with_capacity(1 + data.len());
    payload.push(version_byte);
    payload.extend(data);
    let payload5bit = convert_bits(&payload, 8, 5, true);

    // Generate the 40-bit checksum
    // The prefix used in the checksum calculation is the string prefix's lower 5 bits of each character.
    let checksum_input_len = network.cashaddr_prefix().len() + 1 + payload5bit.len() + 8;
    let mut checksum_input = Vec::with_capacity(checksum_input_len);
    for c in network.cashaddr_prefix().chars() {
        checksum_input.push((c as u8) & 31);
    }
    checksum_input.push(0); // 0 for prefix
    checksum_input.extend(&payload5bit);
    for _ in 0..8 {
        checksum_input.push(0); // Placeholder for checksum
    }
    let checksum = polymod(&checksum_input);

    // Start building the cashaddr string with the prefix first
    let mut cashaddr = String::new();
    cashaddr.push_str(&network.cashaddr_prefix());
    cashaddr.push(':');

    // Encode the rest of the cashaddr string (payload and checksum)
    for d in payload5bit.iter() {
        cashaddr.push(CHARSET[*d as usize] as char);
    }
    for i in (0..8).rev() {
        let c = ((checksum >> (i * 5)) & 31) as u8;
        cashaddr.push(CHARSET[c as usize] as char);
    }

    Ok(cashaddr)
}

/// Cashaddr encodes its data in 5-bit chunks. The spec defines how a stream
/// of bits should be broken up into these 5-bit chunks, which this function performs.
///
/// Every 5 bits in a stream gets its own byte, right aligned. If there are any bits
/// leftover that don't fill a full 5-bit group, they are padded with zeros on the right
/// to create a 5-bit group and placed one last byte the same way. For example:
///
/// Given 3 bytes with bits labeled alphabetically:
///    [abcdefgh, ijklmnop, qrstuvwx]
/// This function converts to 5 bytes in the form:
///    [000abcde, 000fghij, 000klmno, 000pqrst, 000uvwx0]
///
/// The same idea works in reverse during decoding, going from 5bits to 8bits.
fn convert_bits(data: &[u8], inbits: u8, outbits: u8, pad: bool) -> Vec<u8> {
    assert!(inbits <= 8 && outbits <= 8);
    // num_bytes = ceil(len * 8 / 5)
    let num_bytes = (data.len() * inbits as usize + outbits as usize - 1) / outbits as usize;
    let mut ret = Vec::with_capacity(num_bytes);
    let mut acc: u16 = 0; // accumulator of bits
    let mut num: u8 = 0; // num bits in acc
    let groupmask = (1 << outbits) - 1;
    for d in data.iter() {
        // We push each input chunk into a 16-bit accumulator
        acc = (acc << inbits) | (*d as u16);
        num += inbits;
        // Then we extract all the output groups we can
        while num > outbits {
            ret.push((acc >> num - outbits) as u8);
            acc = acc & !(groupmask << num - outbits);
            num = num - outbits;
        }
    }
    if pad {
        // If there's some bits left, pad and add it
        if num > 0 {
            ret.push((acc << outbits - num) as u8);
        }
    } else {
        // If there's some bits left, figure out if we need to remove padding and add it
        let padding = (data.len() * inbits as usize) % outbits as usize;
        if num as usize > padding {
            ret.push((acc >> padding) as u8);
        }
    }
    ret
}

// Calculates a 40-bit checksum given a vector of 5-bit values. The checksum is a BCH code
// over GF(32). The Bitcoin ABC implementation describes this function in detail.
fn polymod(v: &Vec<u8>) -> u64 {
    let mut c: u64 = 1;
    for d in v.iter() {
        let c0: u8 = (c >> 35) as u8;
        c = ((c & 0x07ffffffff) << 5) ^ (*d as u64);
        if c0 & 0x01 != 0 {
            c = c ^ 0x98f2bc8e61;
        }
        if c0 & 0x02 != 0 {
            c = c ^ 0x79b76d99e2;
        }
        if c0 & 0x04 != 0 {
            c = c ^ 0xf33e5fb3c4;
        }
        if c0 & 0x08 != 0 {
            c = c ^ 0xae2eabe2a8;
        }
        if c0 & 0x10 != 0 {
            c = c ^ 0x1e4f43e470;
        }
    }
    c ^ 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn cashaddr_successes() {
        // 20-byte public key hash on mainnet
        verify(
            Network::Mainnet,
            AddressType::P2PKH,
            &hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap(),
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        );

        // 20-byte script on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap(),
            "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
        );

        // 24-byte public key hash on mainnet
        verify(
            Network::Mainnet,
            AddressType::P2PKH,
            &hex::decode("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA").unwrap(),
            "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
        );

        // 24-byte script on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode("7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA").unwrap(),
            "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr",
        );

        // 28-byte public key hash on mainnet
        verify(
            Network::Mainnet,
            AddressType::P2PKH,
            &hex::decode("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B").unwrap(),
            "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
        );

        // 28-byte script on on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode("3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B").unwrap(),
            "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt",
        );

        // 32-byte public key hash on mainnet
        verify(
            Network::Mainnet,
            AddressType::P2PKH,
            &hex::decode("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060")
                .unwrap(),
            "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
        );

        // 32-byte script on on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060")
                .unwrap(),
            "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6",
        );

        // 40-byte public key hash on mainnet
        verify(
            Network::Mainnet,
            AddressType::P2PKH,
            &hex::decode("C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB").unwrap(),
            "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
        );

        // 40-byte script on on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode(
                "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB",
            ).unwrap(),
            "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej",
        );

        // 48-byte public key hash on mainnet
        verify(
            Network::Mainnet,
            AddressType::P2PKH,
            &hex::decode("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C").unwrap(),
            "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
        );

        // 48-byte script on on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode("E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C").unwrap(),
            "bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x",
        );

        // 56-byte public key hash on mainnet
        verify(
            Network::Mainnet,
            AddressType::P2PKH,
            &hex::decode("D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041").unwrap(),
            "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f",
        );

        // 56-byte script on on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode("D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041").unwrap(),
            "bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g",
        );

        // 64-byte public key hash on mainnet
        verify(
            Network::Mainnet,
            AddressType::P2PKH,
            &hex::decode("D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B").unwrap(),
            "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
        );

        // 64-byte script on on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode("D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B").unwrap(),
            "bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez",
        );

        // 64-byte uppercase script on on testnet
        verify(
            Network::Testnet,
            AddressType::P2SH,
            &hex::decode("D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B").unwrap(),
            "BCHTEST:PLG0X333P4238K0QRC5EJ7RZFW5G8E4A4R6VVZYRCY8J3S5K0EN7CALVCLHW46HUDK5FLTTJ6YDVJC0PV3NCHP52AMK97TQA5ZYGG96MC773CWEZ",
        );
    }

    fn verify(network: Network, addr_type: AddressType, data: &Vec<u8>, cashaddr: &str) {
        assert!(
            cashaddr_encode(data, addr_type, network).unwrap() == cashaddr.to_ascii_lowercase()
        );
        let decoded = cashaddr_decode(cashaddr, network).unwrap();
        assert!(decoded.0 == *data);
        assert!(decoded.1 == addr_type);
    }

    #[test]
    fn cashaddr_failures() {
        // Bad sizes
        assert!(cashaddr_encode(&[0; 0], AddressType::P2PKH, Network::Mainnet).is_err());
        assert!(cashaddr_encode(&[0; 19], AddressType::P2PKH, Network::Mainnet).is_err());
        assert!(cashaddr_encode(&[0; 21], AddressType::P2PKH, Network::Mainnet).is_err());
        assert!(cashaddr_encode(&[0; 511], AddressType::P2PKH, Network::Mainnet).is_err());
        assert!(cashaddr_encode(&[0; 10224], AddressType::P2PKH, Network::Mainnet).is_err());

        // Mixed case
        assert!(cashaddr_decode("abc123ABC", Network::Mainnet).is_err());

        // No prefix
        let addr = "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert!(cashaddr_decode(&addr, Network::Mainnet).is_err());

        // Too many prefixes
        let addr = "bitcoincash:bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert!(cashaddr_decode(&addr, Network::Mainnet).is_err());

        // Unexpected prefix
        let addr = "bch:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
        assert!(cashaddr_decode(&addr, Network::Mainnet).is_err());

        // Non-ascii characters  - 'é' at the end
        let addr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekgé";
        assert!(cashaddr_decode(&addr, Network::Mainnet).is_err());

        // Invalid cashaddr characters - '1' at the end
        let addr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg1";
        assert!(cashaddr_decode(&addr, Network::Mainnet).is_err());

        // Bad checksum - last digit changed from 2 to 3
        let addr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3";
        assert!(cashaddr_decode(&addr, Network::Mainnet).is_err());

        // Wrong version byte size
        let cashaddr = encode_with_version_byte(
            &[1; 20],
            version_byte_flags::SIZE_512 | version_byte_flags::TYPE_P2PKH,
            Network::Mainnet,
        ).unwrap();
        assert!(cashaddr_decode(&cashaddr, Network::Mainnet).is_err());

        // Wrong version byte type
        let cashaddr = encode_with_version_byte(
            &[1; 20],
            version_byte_flags::SIZE_160 | 0x09,
            Network::Mainnet,
        ).unwrap();
        assert!(cashaddr_decode(&cashaddr, Network::Mainnet).is_err());
    }
}
