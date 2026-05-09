use std::convert::TryInto;
use crate::zip_crypto::ZipCryptoContext;

const LOCAL_FILE_HEADER_SIG: u32 = 0x04034b50;
const CENTRAL_DIR_SIG: u32 = 0x02014b50;
const END_CENTRAL_DIR_SIG: u32 = 0x06054b50;

struct LocalFileHeader {
    flags: u16,
    compression_method: u16,
    last_mod_time: u16,
    crc32: u32,
    compressed_size: u32,
    filename_len: u16,
    extra_len: u16,
}

fn parse_local_file_header(data: &[u8], offset: usize) -> Option<LocalFileHeader> {
    if offset + 30 > data.len() {
        return None;
    }
    let sig = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    if sig != LOCAL_FILE_HEADER_SIG {
        return None;
    }
    Some(LocalFileHeader {
        flags: u16::from_le_bytes(data[offset + 6..offset + 8].try_into().ok()?),
        compression_method: u16::from_le_bytes(data[offset + 8..offset + 10].try_into().ok()?),
        last_mod_time: u16::from_le_bytes(data[offset + 10..offset + 12].try_into().ok()?),
        crc32: u32::from_le_bytes(data[offset + 14..offset + 18].try_into().ok()?),
        compressed_size: u32::from_le_bytes(data[offset + 18..offset + 22].try_into().ok()?),
        filename_len: u16::from_le_bytes(data[offset + 26..offset + 28].try_into().ok()?),
        extra_len: u16::from_le_bytes(data[offset + 28..offset + 30].try_into().ok()?),
    })
}

fn find_next_local_header(data: &[u8], start: usize) -> Option<usize> {
    let end = data.len().saturating_sub(4);
    for i in start..end {
        if u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0u8; 4])) == LOCAL_FILE_HEADER_SIG
        {
            return Some(i);
        }
    }
    None
}

fn find_first_encrypted_entry(data: &[u8]) -> Option<(usize, usize, LocalFileHeader)> {
    let len = data.len();
    let mut offset = 0;
    let mut entry_index = 0;

    while offset + 30 <= len {
        let hdr = parse_local_file_header(data, offset)?;

        if hdr.flags & 1 != 0 {
            return Some((entry_index, offset, hdr));
        }
        if hdr.flags & (1 << 6) != 0 {
            return Some((entry_index, offset, hdr));
        }

        let hdr_size = 30 + hdr.filename_len as usize + hdr.extra_len as usize;
        let is_dir = hdr.filename_len > 0
            && data.get(offset + 30 + hdr.filename_len as usize - 1) == Some(&b'/');

        if is_dir {
            offset += hdr_size;
        } else if hdr.flags & (1 << 3) != 0 && hdr.compressed_size == 0 {
            let next = find_next_local_header(data, offset + hdr_size)?;
            offset = next;
        } else {
            offset += hdr_size + hdr.compressed_size as usize;
        }
        entry_index += 1;
    }
    None
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let len = data.len();
    if len < 22 {
        return None;
    }
    let search_start = if len > 65557 { len - 65557 } else { 0 };
    for i in (search_start..len - 21).rev() {
        if u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0u8; 4])) == END_CENTRAL_DIR_SIG
        {
            let comment_len =
                u16::from_le_bytes(data[i + 20..i + 22].try_into().unwrap_or([0u8; 2])) as usize;
            if i + 22 + comment_len == len {
                return Some(i);
            }
        }
    }
    None
}

fn find_central_dir_entry(data: &[u8], entry_index: usize) -> Option<(u32, u16)> {
    let eocd_pos = find_eocd(data)?;
    let cd_offset = u32::from_le_bytes(
        data[eocd_pos + 16..eocd_pos + 20]
            .try_into()
            .unwrap_or([0u8; 4]),
    ) as usize;

    let mut offset = cd_offset;
    for idx in 0..=entry_index {
        if offset + 46 > data.len() {
            return None;
        }
        let sig = u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .unwrap_or([0u8; 4]),
        );
        if sig != CENTRAL_DIR_SIG {
            return None;
        }
        if idx == entry_index {
            let crc32 = u32::from_le_bytes(
                data[offset + 16..offset + 20]
                    .try_into()
                    .unwrap_or([0u8; 4]),
            );
            let last_mod_time = u16::from_le_bytes(
                data[offset + 12..offset + 14]
                    .try_into()
                    .unwrap_or([0u8; 2]),
            );
            return Some((crc32, last_mod_time));
        }
        // Skip to next central directory entry
        let fnlen = u16::from_le_bytes(
            data[offset + 28..offset + 30]
                .try_into()
                .unwrap_or([0u8; 2]),
        ) as usize;
        let extralen = u16::from_le_bytes(
            data[offset + 30..offset + 32]
                .try_into()
                .unwrap_or([0u8; 2]),
        ) as usize;
        let commentlen = u16::from_le_bytes(
            data[offset + 32..offset + 34]
                .try_into()
                .unwrap_or([0u8; 2]),
        ) as usize;
        offset += 46 + fnlen + extralen + commentlen;
    }
    None
}

pub(crate) fn extract_zip_info(data: &[u8]) -> Option<ZipCryptoContext> {
    let (entry_index, entry_offset, hdr) = find_first_encrypted_entry(data)?;

    let header_size = 30 + hdr.filename_len as usize + hdr.extra_len as usize;

    if hdr.flags & (1 << 6) != 0 {
        eprintln!("ZIP uses AES/strong encryption (bit 6). Only PKWARE traditional encryption is supported.");
        return None;
    }

    // Extract 12-byte encryption header
    if entry_offset + header_size + 12 > data.len() {
        return None;
    }
    let mut enc_header = [0u8; 12];
    enc_header.copy_from_slice(&data[entry_offset + header_size..entry_offset + header_size + 12]);

    // Extract encrypted payload (after the 12-byte header)
    let payload_start = entry_offset + header_size + 12;
    let encrypted_payload = if hdr.compressed_size > 12 {
        let payload_len = hdr.compressed_size as usize - 12;
        data[payload_start..payload_start + payload_len].to_vec()
    } else {
        // Data descriptor or unreliable size — scan to next entry
        let next = find_next_local_header(data, payload_start)?;
        data[payload_start..next].to_vec()
    };

    // CRC and time from central directory (matched by entry index)
    let (cd_crc32, cd_time) = find_central_dir_entry(data, entry_index)
        .unwrap_or((hdr.crc32, hdr.last_mod_time));

    let using_dd = hdr.flags & (1 << 3) != 0;
    let check_byte = if using_dd {
        ((cd_time >> 8) & 0xFF) as u8
    } else {
        ((cd_crc32 >> 24) & 0xFF) as u8
    };

    let stored_crc = cd_crc32;
    let compression_method = hdr.compression_method; // use local header's method, not CD

    Some(ZipCryptoContext {
        enc_header,
        encrypted_payload,
        check_byte,
        stored_crc,
        compression_method,
    })
}
