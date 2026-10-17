use crate::zip_aes::AesContext;
use crate::zip_crypto::ZipCryptoContext;

pub(crate) enum ZipEncryption {
    Traditional(ZipCryptoContext),
    Aes(AesContext),
}

const LOCAL_FILE_HEADER_SIG: u32 = 0x04034b50;
const CENTRAL_DIR_SIG: u32 = 0x02014b50;
const END_CENTRAL_DIR_SIG: u32 = 0x06054b50;
const AES_COMPRESSION_METHOD: u16 = 99;
const AES_EXTRA_FIELD_ID: u16 = 0x9901;

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
        if u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0u8; 4]))
            == LOCAL_FILE_HEADER_SIG
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
    let search_start = len.saturating_sub(65557);
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

struct CentralDirEntry {
    crc32: u32,
    last_mod_time: u16,
    compressed_size: u32,
}

fn find_central_dir_entry(data: &[u8], entry_index: usize) -> Option<CentralDirEntry> {
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
        let sig = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0u8; 4]));
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
            let compressed_size = u32::from_le_bytes(
                data[offset + 20..offset + 24]
                    .try_into()
                    .unwrap_or([0u8; 4]),
            );
            return Some(CentralDirEntry {
                crc32,
                last_mod_time,
                compressed_size,
            });
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

/// Locates the WinZip AES extra field (0x9901) and returns
/// (version, strength, actual compression method).
fn find_aes_extra_field(
    data: &[u8],
    extra_start: usize,
    extra_len: usize,
) -> Option<(u16, u8, u16)> {
    let end = extra_start.checked_add(extra_len)?;
    if end > data.len() {
        return None;
    }

    let mut offset = extra_start;
    while offset + 4 <= end {
        let id = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
        let size = u16::from_le_bytes(data[offset + 2..offset + 4].try_into().ok()?) as usize;
        let field_start = offset + 4;
        if field_start + size > end {
            break;
        }
        if id == AES_EXTRA_FIELD_ID && size == 7 {
            let version = u16::from_le_bytes(data[field_start..field_start + 2].try_into().ok()?);
            let vendor = &data[field_start + 2..field_start + 4];
            let strength = data[field_start + 4];
            let method =
                u16::from_le_bytes(data[field_start + 5..field_start + 7].try_into().ok()?);
            if vendor == b"AE" {
                return Some((version, strength, method));
            }
        }
        offset = field_start + size;
    }
    None
}

fn extract_aes_info(
    data: &[u8],
    entry_offset: usize,
    hdr: &LocalFileHeader,
    cd_entry: Option<&CentralDirEntry>,
) -> Option<AesContext> {
    let filename_len = hdr.filename_len as usize;
    let extra_start = entry_offset + 30 + filename_len;
    let (version, strength, _method) =
        match find_aes_extra_field(data, extra_start, hdr.extra_len as usize) {
            Some(info) => info,
            None => {
                eprintln!(
                    "ZIP uses strong encryption but has no WinZip AES extra field \
                 (PKWARE strong encryption is not supported)."
                );
                return None;
            }
        };

    if version != 1 && version != 2 {
        eprintln!("Unsupported WinZip AES version: {version}");
        return None;
    }

    let (key_len, salt_len): (usize, usize) = match strength {
        1 => (16, 8),
        2 => (24, 12),
        3 => (32, 16),
        _ => {
            eprintln!("Unsupported WinZip AES strength value: {strength}");
            return None;
        }
    };

    let payload_start = entry_offset + 30 + filename_len + hdr.extra_len as usize;
    let overhead = salt_len + 2 + 10;

    // The sizes in the headers include salt, password verifier and
    // authentication code. Fall back to the central directory or a header
    // scan when the local header has no reliable size (data descriptor).
    let local_size = hdr.compressed_size as usize;
    let cd_size = cd_entry.map(|e| e.compressed_size as usize).unwrap_or(0);
    let usable = |total: usize| total >= overhead && payload_start + total <= data.len();

    let total = if usable(local_size) {
        local_size
    } else if usable(cd_size) {
        cd_size
    } else {
        let scanned = find_next_local_header(data, payload_start)? - payload_start;
        if !usable(scanned) {
            return None;
        }
        scanned
    };

    let ciphertext_start = payload_start + salt_len + 2;
    let ciphertext_end = payload_start + total - 10;

    let mut salt = vec![0u8; salt_len];
    salt.copy_from_slice(&data[payload_start..payload_start + salt_len]);

    let mut verifier = [0u8; 2];
    verifier.copy_from_slice(&data[payload_start + salt_len..ciphertext_start]);

    let mut auth_code = [0u8; 10];
    auth_code.copy_from_slice(&data[ciphertext_end..payload_start + total]);

    Some(AesContext {
        salt,
        verifier,
        auth_code,
        ciphertext: ciphertext_start..ciphertext_end,
        key_len,
    })
}

pub(crate) fn extract_zip_info(data: &[u8]) -> Option<ZipEncryption> {
    let (entry_index, entry_offset, hdr) = find_first_encrypted_entry(data)?;
    let cd_entry = find_central_dir_entry(data, entry_index);

    // 7-Zip writes AES entries with compression method 99 but leaves the
    // strong-encryption flag (bit 6) unset; WinZip sets both.
    if hdr.compression_method == AES_COMPRESSION_METHOD || hdr.flags & (1 << 6) != 0 {
        return extract_aes_info(data, entry_offset, &hdr, cd_entry.as_ref())
            .map(ZipEncryption::Aes);
    }

    let header_size = 30 + hdr.filename_len as usize + hdr.extra_len as usize;

    // Extract 12-byte encryption header
    if entry_offset + header_size + 12 > data.len() {
        return None;
    }
    let mut enc_header = [0u8; 12];
    enc_header.copy_from_slice(&data[entry_offset + header_size..entry_offset + header_size + 12]);

    // Extract encrypted payload (after the 12-byte header)
    let payload_start = entry_offset + header_size + 12;
    let payload = if hdr.compressed_size > 12 {
        let payload_len = hdr.compressed_size as usize - 12;
        payload_start..payload_start + payload_len
    } else {
        // Data descriptor or unreliable size; scan to next entry
        let next = find_next_local_header(data, payload_start)?;
        payload_start..next
    };

    // CRC and time from central directory (matched by entry index)
    let (cd_crc32, cd_time) = cd_entry
        .map(|e| (e.crc32, e.last_mod_time))
        .unwrap_or((hdr.crc32, hdr.last_mod_time));

    let using_dd = hdr.flags & (1 << 3) != 0;
    let check_byte = if using_dd {
        ((cd_time >> 8) & 0xFF) as u8
    } else {
        ((cd_crc32 >> 24) & 0xFF) as u8
    };

    let stored_crc = cd_crc32;
    let compression_method = hdr.compression_method; // use local header's method, not CD

    Some(ZipEncryption::Traditional(ZipCryptoContext {
        enc_header,
        payload,
        check_byte,
        stored_crc,
        compression_method,
    }))
}
