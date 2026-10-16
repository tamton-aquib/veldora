use pdf::backend::Backend;
use pdf::object::Resolve;
use pdf::primitive::{Dictionary, Primitive};

pub struct PdfCryptoContext {
    pub o: [u8; 48],
    pub o_len: usize,
    pub u: [u8; 48],
    pub u_len: usize,
    pub oe: [u8; 32],
    pub ue: [u8; 32],
    pub perms: [u8; 16],
    pub id: [u8; 32],
    pub id_len: usize,
    pub p: i32,
    pub r: u32,
    pub v: i32,
    pub key_size: usize,
    pub encrypt_metadata: bool,
}

fn get_cf_length(dict: &Dictionary, res: &impl Resolve) -> Option<u32> {
    let cf = dict.get("CF")?;
    let cf_dict = cf.clone().into_dictionary(res).ok()?;
    let stdcf = cf_dict.get("StdCF")?;
    let stdcf_dict = stdcf.clone().into_dictionary(res).ok()?;
    let length = stdcf_dict.get("Length")?;
    length.as_integer().ok().map(|l| l as u32)
}

fn get_string_bytes(dict: &Dictionary, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(dict
        .get(key)
        .ok_or_else(|| format!("Missing /{} in Encrypt dictionary", key))?
        .as_string()
        .map_err(|_| format!("Invalid /{} in Encrypt dictionary", key))?
        .data
        .clone())
}

fn get_integer(dict: &Dictionary, key: &str) -> Result<i32, Box<dyn std::error::Error>> {
    Ok(dict
        .get(key)
        .ok_or_else(|| format!("Missing /{} in Encrypt dictionary", key))?
        .as_integer()
        .map_err(|_| format!("Invalid /{} in Encrypt dictionary", key))?)
}

impl PdfCryptoContext {
    pub fn from_file(filename: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_bytes(std::fs::read(filename)?)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self, Box<dyn std::error::Error>> {
        let start_offset = data.locate_start_offset()?;
        let (refs, trailer) = data.read_xref_table_and_trailer(start_offset)?;
        let storage = pdf::file::Storage::new(data, refs, start_offset);

        let encrypt_primitive = trailer
            .get("Encrypt")
            .ok_or("PDF file is not encrypted")?
            .clone();

        let encrypt_dict = match encrypt_primitive {
            Primitive::Dictionary(d) => d,
            Primitive::Reference(r) => match storage.resolve(r)? {
                Primitive::Dictionary(d) => d,
                _ => return Err("Encrypt is not a dictionary".into()),
            },
            _ => return Err("Invalid Encrypt entry".into()),
        };

        let o_bytes = get_string_bytes(&encrypt_dict, "O")?;
        let u_bytes = get_string_bytes(&encrypt_dict, "U")?;
        let r_val = get_integer(&encrypt_dict, "R")? as u32;
        let p_val = get_integer(&encrypt_dict, "P")?;
        let v_val = get_integer(&encrypt_dict, "V")?;
        let encrypt_metadata = encrypt_dict
            .get("EncryptMetadata")
            .and_then(|p| p.as_bool().ok())
            .unwrap_or(true);

        let id = trailer
            .get("ID")
            .and_then(|p| p.as_array().ok())
            .and_then(|arr| arr.first())
            .and_then(|p| p.as_string().ok())
            .map(|s| s.data.clone())
            .unwrap_or_default();

        // Follow the same inference rules as pdf.js: the top-level /Length is
        // in bits; when it is missing, the crypt filter /Length is normally in
        // bytes (e.g. 16) but some producers store bits (e.g. 128) there.
        let key_bits = if v_val >= 4 {
            let top_level = encrypt_dict
                .get("Length")
                .and_then(|len| len.as_integer().ok())
                .map(|len| len as u32);
            match top_level {
                Some(bits) => bits,
                None => get_cf_length(&encrypt_dict, &storage)
                    .map(|n| if n < 40 { n * 8 } else { n })
                    .unwrap_or(if v_val >= 5 { 256 } else { 128 }),
            }
        } else if v_val == 2 {
            encrypt_dict
                .get("Length")
                .and_then(|len| len.as_integer().ok())
                .map(|len| len as u32)
                .unwrap_or(40)
        } else {
            40
        };

        // Guard against malformed values: revisions up to 4 support 40 to 128
        // bit keys, revision 5 and 6 use 256 bit keys. Anything else would
        // overflow the key derivation buffers.
        let max_bits = if v_val >= 5 { 256 } else { 128 };
        let key_bits = if key_bits < 40 || key_bits % 8 != 0 || key_bits > max_bits {
            max_bits
        } else {
            key_bits
        };

        let id_len = id.len().min(32);
        let o_len = o_bytes.len().min(48);
        let u_len = u_bytes.len().min(48);

        let oe_bytes = if v_val >= 5 {
            get_string_bytes(&encrypt_dict, "OE").ok()
        } else {
            None
        };
        let ue_bytes = if v_val >= 5 {
            get_string_bytes(&encrypt_dict, "UE").ok()
        } else {
            None
        };
        let perms_bytes = if v_val >= 5 {
            get_string_bytes(&encrypt_dict, "Perms").ok()
        } else {
            None
        };

        let oe_len = oe_bytes.as_ref().map(|b| b.len().min(32)).unwrap_or(0);
        let ue_len = ue_bytes.as_ref().map(|b| b.len().min(32)).unwrap_or(0);
        let perms_len = perms_bytes.as_ref().map(|b| b.len().min(16)).unwrap_or(0);

        let mut ctx = Self {
            o: [0u8; 48],
            o_len,
            u: [0u8; 48],
            u_len,
            oe: [0u8; 32],
            ue: [0u8; 32],
            perms: [0u8; 16],
            id: [0u8; 32],
            id_len,
            p: p_val,
            r: r_val,
            v: v_val,
            key_size: (key_bits / 8) as usize,
            encrypt_metadata,
        };
        ctx.o[..o_len].copy_from_slice(&o_bytes[..o_len]);
        ctx.u[..u_len].copy_from_slice(&u_bytes[..u_len]);
        if let Some(b) = oe_bytes {
            ctx.oe[..oe_len].copy_from_slice(&b[..oe_len]);
        }
        if let Some(b) = ue_bytes {
            ctx.ue[..ue_len].copy_from_slice(&b[..ue_len]);
        }
        if let Some(b) = perms_bytes {
            ctx.perms[..perms_len].copy_from_slice(&b[..perms_len]);
        }
        ctx.id[..id_len].copy_from_slice(&id[..id_len]);
        Ok(ctx)
    }
}
