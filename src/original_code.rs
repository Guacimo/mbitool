use crate::mbi::{
    AHAB_CONTAINER_VERSION, AHAB_HASH_SHA384, AHAB_HASH_SHA512, AHAB_KEY_SIZE_P384,
    AHAB_SIGBLK_VERSION, AHAB_SIGN_ALGO_ECDSA, AHAB_SIGN_ALGO_ML_DSA, AHAB_SRK_TABLE_V2_VERSION,
    ECC_P384_COORD_LEN, ImageEntry, TAG_AHAB_CONTAINER_HEADER, TAG_AHAB_SIGNATURE,
    TAG_AHAB_SIGNATURE_BLOCK, TAG_AHAB_SRK_ARRAY, TAG_AHAB_SRK_DATA, TAG_AHAB_SRK_RECORD,
    TAG_AHAB_SRK_TABLE_V2,
};

use sha2::{Digest, Sha384, Sha512};

use anyhow::anyhow;

fn le_u16(v: usize) -> anyhow::Result<[u8; 2]> {
    if v > 0xFFFF {
        return Err(anyhow!("value too large for u16: {v}"));
    }
    Ok((v as u16).to_le_bytes())
}

pub fn srk_data_export(pub_key_raw: &[u8], srk_id: u8) -> anyhow::Result<Vec<u8>> {
    // [version][len_le][tag] + [srk_id,reserved,reserved,reserved] + key
    let total_len = 8usize
        .checked_add(pub_key_raw.len())
        .ok_or_else(|| anyhow!("srk_data length overflow"))?;
    let len_le = le_u16(total_len)?;

    let mut out = Vec::with_capacity(total_len);
    out.push(0x00);
    out.extend_from_slice(&len_le);
    out.push(TAG_AHAB_SRK_DATA);
    out.extend_from_slice(&[srk_id, 0x00, 0x00, 0x00]);
    out.extend_from_slice(pub_key_raw);
    println!(
        "Srk data export: pub_key: {:02x?}, srk_id: {:02x?} out: {:02x?}",
        pub_key_raw, srk_id, out
    );
    Ok(out)
}

pub fn srk_data_hash_64(srk_data_bytes: &[u8], hash_tag: u8) -> anyhow::Result<[u8; 64]> {
    match hash_tag {
        AHAB_HASH_SHA512 => {
            let digest = Sha512::digest(srk_data_bytes);
            let mut out = [0u8; 64];
            out.copy_from_slice(&digest);
            Ok(out)
        }
        AHAB_HASH_SHA384 => {
            let digest = Sha384::digest(srk_data_bytes);
            let mut out = [0u8; 64];
            out[..48].copy_from_slice(&digest);
            Ok(out)
        }
        _ => Err(anyhow!("unsupported hash tag 0x{hash_tag:02X}")),
    }
}

// SRK ARRAY BUILDER
fn build_srk_array_hybrid(
    ecdsa: &[[u8; ECC_P384_COORD_LEN * 2]],
    mldsa: &[Vec<u8>],
    used_srk_id: u8,
) -> anyhow::Result<Vec<u8>> {
    if ecdsa.len() != 4 {
        return Err(anyhow!("ECDSA SRK list must contain 4 keys"));
    }
    if mldsa.len() != 4 {
        return Err(anyhow!("ML-DSA SRK list must contain 4 keys"));
    }
    if used_srk_id > 3 {
        return Err(anyhow!("used_srk_id out of range: {used_srk_id}"));
    }

    let ecdsa_arr: [[u8; ECC_P384_COORD_LEN * 2]; 4] = [ecdsa[0], ecdsa[1], ecdsa[2], ecdsa[3]];
    let mldsa_arr: [Vec<u8>; 4] = [
        mldsa[0].clone(),
        mldsa[1].clone(),
        mldsa[2].clone(),
        mldsa[3].clone(),
    ];

    let table0 = srk_table_v2_export_ecdsa_p384(&ecdsa_arr)?;
    let table1 = srk_table_v2_export_mldsa(&mldsa_arr)?;

    let used = used_srk_id as usize;
    let srk_data_ecdsa = srk_data_export(&ecdsa_arr[used], used_srk_id)?;
    let srk_data_mldsa = srk_data_export(&mldsa_arr[used], used_srk_id)?;

    let total_len =
        8usize + table0.len() + table1.len() + srk_data_ecdsa.len() + srk_data_mldsa.len();

    // For mcxn556s hybrid mode we observed a fixed 0xD00 SRK array region.
    if total_len > 0xD00 {
        return Err(anyhow!("SRK array too large: 0x{total_len:X}"));
    }

    let mut out = Vec::with_capacity(0xD00);
    out.push(0x00); // version
    out.extend_from_slice(&le_u16(0xD00)?);
    out.push(TAG_AHAB_SRK_ARRAY);
    out.extend_from_slice(&0u32.to_le_bytes());
    out[4] = 2; // srk_table_count in the low byte of word1

    out.extend_from_slice(&table0);
    out.extend_from_slice(&srk_data_ecdsa);
    out.extend_from_slice(&table1);
    out.extend_from_slice(&srk_data_mldsa);

    // Zero-pad to the fixed length.
    out.resize(0xD00, 0);
    Ok(out)
}

pub fn srk_table_v2_export_ecdsa_p384(
    keys: &[[u8; ECC_P384_COORD_LEN * 2]; 4],
) -> anyhow::Result<Vec<u8>> {
    let mut records = Vec::with_capacity(4);
    for (idx, xy) in keys.iter().enumerate() {
        records.push(srk_record_v2_export_ecdsa_p384(xy, idx as u8)?);
    }
    let table_len = 4usize + records.iter().map(|r| r.len()).sum::<usize>();
    let len_le = le_u16(table_len)?;

    let mut out = Vec::with_capacity(table_len);
    out.push(TAG_AHAB_SRK_TABLE_V2);
    out.extend_from_slice(&len_le);
    out.push(AHAB_SRK_TABLE_V2_VERSION);
    for rec in records {
        out.extend_from_slice(&rec);
    }
    Ok(out)
}

pub fn srk_table_v2_export_mldsa(keys: &[Vec<u8>; 4]) -> anyhow::Result<Vec<u8>> {
    let mut records = Vec::with_capacity(4);
    for (idx, key) in keys.iter().enumerate() {
        records.push(srk_record_v2_export_mldsa(key, idx as u8)?);
    }
    let table_len = 4usize + records.iter().map(|r| r.len()).sum::<usize>();
    let len_le = le_u16(table_len)?;

    let mut out = Vec::with_capacity(table_len);
    out.push(TAG_AHAB_SRK_TABLE_V2);
    out.extend_from_slice(&len_le);
    out.push(AHAB_SRK_TABLE_V2_VERSION);
    for rec in records {
        out.extend_from_slice(&rec);
    }
    Ok(out)
}

pub fn mldsa_params_for_pub_len(pub_len: usize) -> anyhow::Result<(u8, u8)> {
    match pub_len {
        1952 => Ok((0x09, AHAB_HASH_SHA384)),
        2592 => Ok((0x0A, AHAB_HASH_SHA512)),
        _ => Err(anyhow!(
            "unsupported ML-DSA public key length {pub_len} (expected 1952 or 2592)"
        )),
    }
}

fn srk_record_v2_export_ecdsa_p384(
    xy: &[u8; ECC_P384_COORD_LEN * 2],
    srk_id: u8,
) -> anyhow::Result<Vec<u8>> {
    let srk_data = srk_data_export(xy, srk_id)?;
    let crypto_params = srk_data_hash_64(&srk_data, AHAB_HASH_SHA384)?;

    let record_len = 12usize + 64usize;
    let len_le = le_u16(record_len)?;
    let p_len = le_u16(ECC_P384_COORD_LEN)?;

    let mut out = Vec::with_capacity(record_len);
    out.push(TAG_AHAB_SRK_RECORD);
    out.extend_from_slice(&len_le);
    out.push(AHAB_SIGN_ALGO_ECDSA);

    out.push(AHAB_HASH_SHA384);
    out.push(AHAB_KEY_SIZE_P384);
    out.push(0x00);
    out.push(0x00);

    out.extend_from_slice(&p_len);
    out.extend_from_slice(&p_len);
    out.extend_from_slice(&crypto_params);
    Ok(out)
}

fn srk_record_v2_export_mldsa(pub_key_raw: &[u8], srk_id: u8) -> anyhow::Result<Vec<u8>> {
    let (key_size_tag, hash_tag) = mldsa_params_for_pub_len(pub_key_raw.len())?;
    let srk_data = srk_data_export(pub_key_raw, srk_id)?;
    let crypto_params = srk_data_hash_64(&srk_data, hash_tag)?;

    let record_len = 12usize + 64usize;
    let len_le = le_u16(record_len)?;
    let p1_len = le_u16(pub_key_raw.len())?;

    let mut out = Vec::with_capacity(record_len);
    out.push(TAG_AHAB_SRK_RECORD);
    out.extend_from_slice(&len_le);
    out.push(AHAB_SIGN_ALGO_ML_DSA);

    out.push(hash_tag);
    out.push(key_size_tag);
    out.push(0x00);
    out.push(0x00);

    out.extend_from_slice(&p1_len);
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&crypto_params);
    Ok(out)
}

fn build_signature_container(tag: u8, total_len: usize) -> anyhow::Result<Vec<u8>> {
    if total_len < 8 || total_len > 0xFFFF {
        return Err(anyhow!(
            "Invalid signature container length 0x{total_len:X}"
        ));
    }
    let mut out = Vec::with_capacity(total_len);
    out.push(0x00); // version
    out.extend_from_slice(&le_u16(total_len)?);
    out.push(tag);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.resize(total_len, 0);
    Ok(out)
}

fn build_signature_block(
    srk_array: &[u8],
    sig1_total_len: usize,
    sig2_total_len: usize,
) -> anyhow::Result<Vec<u8>> {
    if srk_array.len() != 0xD00 {
        return Err(anyhow!(
            "SRK array must be exactly 0xD00 bytes for this builder"
        ));
    }

    let sig1 = build_signature_container(TAG_AHAB_SIGNATURE, sig1_total_len)?;
    let sig2 = build_signature_container(TAG_AHAB_SIGNATURE, sig2_total_len)?;

    let sigblk_len = 0x10usize + srk_array.len() + sig1.len() + sig2.len();
    if sigblk_len > 0xFFFF {
        return Err(anyhow!("Signature block too large: 0x{sigblk_len:X}"));
    }

    // Signature block header words.
    let word0 = ((TAG_AHAB_SIGNATURE_BLOCK as u32) << 24)
        | ((sigblk_len as u32) << 8)
        | (AHAB_SIGBLK_VERSION as u32);
    let srk_off: u16 = 0x10;
    let cert_off: u16 = 0x0000;
    let sig_off: u16 = (0x10usize + srk_array.len()) as u16;
    let word1 = ((srk_off as u32) << 16) | (cert_off as u32);
    let word2 = sig_off as u32;
    let word3 = 0u32;

    let mut out = Vec::with_capacity(sigblk_len);
    out.extend_from_slice(&word0.to_le_bytes());
    out.extend_from_slice(&word1.to_le_bytes());
    out.extend_from_slice(&word2.to_le_bytes());
    out.extend_from_slice(&word3.to_le_bytes());
    out.extend_from_slice(srk_array);
    out.extend_from_slice(&sig1);
    out.extend_from_slice(&sig2);
    Ok(out)
}

/// NOTE AHAB CONTAINER BUILDER
pub fn build_container_multi(
    srk_set: u8,
    used_srk_id: u8,
    fuse_version: u8,
    image_version: u16,
    images: &[ImageEntry],
    sigblk: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    if used_srk_id > 3 {
        return Err(anyhow!("used_srk_id out of range: {used_srk_id}"));
    }
    if images.is_empty() {
        return Err(anyhow!("At least one image is required"));
    }
    if images.len() > 3 {
        return Err(anyhow!("Too many images: {} (max 3)", images.len()));
    }

    let images_count = images.len() as u32;
    // Container layout: 16-byte header + (128 bytes × N images) + signature block
    let sigblk_off = 0x10u32 + (0x80u32 * images_count);
    let container_len = sigblk_off as usize + sigblk.len();

    if container_len > 0xFFFF {
        return Err(anyhow!("Container too large: 0x{container_len:X}"));
    }
    let flags = (srk_set as u32 & 0xF) | (((used_srk_id as u32) & 0x3) << 4);

    let word0 = ((TAG_AHAB_CONTAINER_HEADER as u32) << 24)
        | ((container_len as u32) << 8)
        | (AHAB_CONTAINER_VERSION as u32);
    let word1 = flags;
    let word2 = (images_count << 24) | ((fuse_version as u32) << 16) | (image_version as u32);
    let cert_version: u32 = 0;
    let word3 = (cert_version << 16) | (sigblk_off & 0xFFFF);

    let mut out = Vec::with_capacity(container_len);
    out.extend_from_slice(&word0.to_le_bytes());
    out.extend_from_slice(&word1.to_le_bytes());
    out.extend_from_slice(&word2.to_le_bytes());
    out.extend_from_slice(&word3.to_le_bytes());

    // Write each image entry (0x80 bytes each)
    for img in images {
        out.extend_from_slice(&img.offset.to_le_bytes()); // offset as signed i32
        out.extend_from_slice(&img.size.to_le_bytes());
        out.extend_from_slice(&img.load_address.to_le_bytes());
        out.extend_from_slice(&img.entry_point.to_le_bytes());
        out.extend_from_slice(&img.flags.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // metadata
        out.extend_from_slice(&img.hash);
        out.extend_from_slice(&[0u8; 32]); // IV (zeros for non-encrypted)
    }

    let pre_sigblk_len = 0x10 + (0x80 * images.len());
    if out.len() != pre_sigblk_len {
        return Err(anyhow!(
            "Internal error: container pre-sigblk length 0x{:X} != expected 0x{:X}",
            out.len(),
            pre_sigblk_len
        ));
    }

    out.extend_from_slice(&sigblk);
    if out.len() != container_len {
        return Err(anyhow!(
            "Internal error: container size mismatch got=0x{:X} expected=0x{:X}",
            out.len(),
            container_len
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn produce_result() {
        let ecdsa_xy = [[0xFF; 96], [0xFF; 96], [0xFF; 96], [0xFF; 96]];
        let mldsa_raw = [
            Vec::from([0xAA; 1952]),
            Vec::from([0xAA; 1952]),
            Vec::from([0xAA; 1952]),
            Vec::from([0xAA; 1952]),
        ];
        let used_srk_id = 0x2;

        let srk_array = build_srk_array_hybrid(&ecdsa_xy, &mldsa_raw, used_srk_id)
            .expect("Failed to build srk array");
        let sig1_total_len: usize = 0x68;
        let sig2_total_len: usize = 0x121B;
        let sigblk = build_signature_block(&srk_array, sig1_total_len, sig2_total_len)
            .expect("Failed to build signature block");

        let image_entry = [ImageEntry {
            offset: 0x5,
            size: 0x50,
            load_address: 0x3,
            entry_point: 0x30,
            flags: 0x15,
            hash: [0xFF; 64],
        }];
        let res = build_container_multi(5, used_srk_id, 6, 7, &image_entry, sigblk).expect("Frick");
        println!("Res: {res:02x?}");
    }
}
