use std::io::{Cursor, SeekFrom};

use binrw::binrw;
use binrw::meta::WriteEndian;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use sha2::{Digest, Sha384, Sha512};
use thiserror::Error;

pub const TAG_AHAB_CONTAINER_HEADER: u8 = 0x87;
pub const TAG_AHAB_SRK_ARRAY: u8 = 0x5A;

pub const AHAB_CONTAINER_VERSION: u8 = 0x02;
pub const AHAB_SIGBLK_VERSION: u8 = 0x01;
pub const AHAB_KEY_SIZE_P384: u8 = 0x02;
pub const AHAB_SRK_TABLE_V2_VERSION: u8 = 0x43;

pub const ECC_P384_COORD_LEN: usize = 48;

const MBI_HDR_OFF_TOTAL_LEN: usize = 0x20;

pub trait BinaryLen {
    fn binary_len(&self) -> usize;
}

pub trait AhabHash {
    fn hash(&self, algo: HashAlgorithm) -> Result<[u8; 64], binrw::Error>;
}

pub trait ToVec {
    fn to_vec(&self) -> Result<Vec<u8>, binrw::Error>;
}

impl<T> ToVec for T
where
    T: BinWrite + WriteEndian,
    for<'a> <T as binrw::BinWrite>::Args<'a>: Default,
{
    fn to_vec(&self) -> Result<Vec<u8>, binrw::Error> {
        let mut data = Cursor::new(Vec::new());
        self.write(&mut data)?;
        Ok(data.into_inner())
    }
}

impl<T> AhabHash for T
where
    T: ToVec,
{
    fn hash(&self, algo: HashAlgorithm) -> Result<[u8; 64], binrw::Error> {
        let data = self.to_vec()?;
        Ok(hash(&data, algo))
    }
}

pub fn hash(data: &[u8], algo: HashAlgorithm) -> [u8; 64] {
    let mut out = [0u8; 64];
    match algo {
        HashAlgorithm::Sha512 => {
            out.copy_from_slice(&Sha512::digest(data));
        }
        HashAlgorithm::Sha384 => {
            out[..48].copy_from_slice(&Sha384::digest(data));
        }
    }
    out
}

#[binrw]
#[brw(repr = u8)]
#[derive(Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha384 = 0x01,
    Sha512 = 0x02,
}

#[binrw]
#[brw(repr = u8)]
#[derive(Debug, Eq, PartialEq)]
pub enum SignAlgorithm {
    Mldsa = 0xD2,
    Ecdsa = 0x27,
}

#[binrw]
#[brw(little)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageEntry {
    pub offset: i32,
    pub size: u32,
    pub load_address: u64,
    pub entry_point: u64,
    #[brw(pad_after(4))]
    pub flags: u32,
    #[brw(pad_after(32))]
    pub hash: [u8; 64],
}

impl BinaryLen for ImageEntry {
    fn binary_len(&self) -> usize {
        128
    }
}

#[bitfield]
#[derive(BinWrite, BinRead, Clone, Copy, Debug, Eq, PartialEq)]
#[brw(little)]
#[br(map = Self::from_bytes)]
#[bw(map = |x: &Self| Self::into_bytes(*x))]
pub struct AhabContainerFlags {
    pub srk_set: B4,
    pub used_srk_id: B2,
    #[skip]
    padding: B26,
}

impl BinaryLen for AhabContainerFlags {
    fn binary_len(&self) -> usize {
        4
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq)]
pub struct AhabContainer {
    pub version: u8,
    #[br(temp)]
    #[bw(calc = self.binary_len() as u16)]
    len: u16,
    pub tag: u8,
    pub flags: AhabContainerFlags,
    pub image_version: u16,
    pub fuse_version: u8,
    #[br(temp)]
    #[bw(calc = images.len() as u8)]
    images_count: u8,
    #[br(temp)]
    #[bw(calc = self.signature_block_offset())]
    #[brw(pad_after(2))]
    sigblk_off: u16,
    #[br(count = images_count)]
    pub images: Vec<ImageEntry>,
    pub signature_block: SignatureBlock,
}

impl AhabContainer {
    pub fn signature_block_offset(&self) -> u16 {
        0x10 + (0x80 * self.images.len() as u16)
    }
}

impl BinaryLen for AhabContainer {
    fn binary_len(&self) -> usize {
        0x10 + self.images.iter().map(BinaryLen::binary_len).sum::<usize>()
            + self.signature_block.binary_len()
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq)]
pub struct SignatureContainer {
    #[br(temp)]
    #[bw(calc = 0x0)]
    #[br(assert(version == 0x0, "Incompatible signature container version"))]
    version: u8,
    #[bw(calc = self.binary_len() as u16)]
    len: u16,
    ///TAG_AHAB_SIGNATURE
    #[brw(magic = 0xD8u8)]
    #[br(count = len - 4)]
    pub signature: Vec<u8>,
}

impl BinaryLen for SignatureContainer {
    fn binary_len(&self) -> usize {
        self.signature.len() + 4
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq)]
pub struct SignatureBlock {
    // AHAB_SIGBLK_VERSION
    pub version: u8,
    #[bw(calc = self.binary_len() as u16)]
    len: u16,
    // TAG_AHAB_SIGNATURE_BLOCK
    #[brw(magic = 0x90u8)]
    // 0x0
    pub cert_off: u16,
    // 0x10
    pub srk_off: u16,
    #[brw(pad_after(4))]
    #[bw(calc = (0x10 + srk_array.len) as u32)]
    sig_off: u32,
    #[brw(pad_size_to(0xD00))]
    pub srk_array: SrkArrayHybrid,
    pub signatures: [SignatureContainer; 2],
}

impl BinaryLen for SignatureBlock {
    fn binary_len(&self) -> usize {
        self.srk_array.binary_len()
            + 16
            + self
                .signatures
                .iter()
                .map(BinaryLen::binary_len)
                .sum::<usize>()
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq)]
pub struct SrkRecordEcsda {
    // TAG_AHAB_SRK_RECORD 0xE1
    #[brw(magic = 0xE1u8)]
    // In the code as 12 + 64
    #[bw(calc = self.binary_len() as u16)]
    len: u16,
    // AHAB_SIGN_ALGO_ECSDA 0x27
    pub sign_algorithm: SignAlgorithm,
    // AHAB_HASH_SHA384 0x01
    pub hash_algorithm: HashAlgorithm,
    // AHAB_KEY_SIZE_P384 0x02
    #[brw(pad_after(2))]
    pub key_size: u8,
    pub p_len_x: u16,
    pub p_len_y: u16,
    #[br(count = len - 12)]
    pub crypto_params: Vec<u8>,
}

impl BinaryLen for SrkRecordEcsda {
    fn binary_len(&self) -> usize {
        self.crypto_params.len() + 12
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq)]
pub struct SrkRecordMldsa {
    // TAG_AHAB_SRK_RECORD 0xE1
    #[brw(magic = 0xE1u8)]
    // 12 + 64?
    #[bw(calc = self.binary_len() as u16)]
    len: u16,
    // AHAB_SIGN_ALGO_ML_DSA 0xD2
    pub sign_algorithm: SignAlgorithm,
    // AHAB_HASH_SHA384 0x01
    pub hash_algorithm: HashAlgorithm,
    #[brw(pad_after(2))]
    pub key_size: u8,
    #[brw(pad_after(2))]
    pub p_len: u16,
    #[br(count = len - 12)]
    pub crypto_params: Vec<u8>,
}

impl BinaryLen for SrkRecordMldsa {
    fn binary_len(&self) -> usize {
        self.crypto_params.len() + 12
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq)]
pub struct SrkTableEcsdaP384 {
    // TAG_AHAB_SRK_TABLE_V2
    #[brw(magic = 0xD7u8)]
    #[bw(calc = self.binary_len() as u16)]
    len: u16,
    #[br(temp)]
    #[bw(calc = AHAB_SRK_TABLE_V2_VERSION)]
    #[br(assert(version == AHAB_SRK_TABLE_V2_VERSION, "Incompatible srk table version"))]
    version: u8,
    pub records: [SrkRecordEcsda; 4],
}

impl BinaryLen for SrkTableEcsdaP384 {
    fn binary_len(&self) -> usize {
        4 + self
            .records
            .iter()
            .map(|r| r.crypto_params.len() + 12)
            .sum::<usize>()
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq)]
pub struct SrkTableMldsa {
    // TAG_AHAB_SRK_TABLE_V2
    #[brw(magic = 0xD7u8)]
    #[bw(calc = self.binary_len() as u16)]
    len: u16,
    #[br(temp)]
    #[bw(calc = AHAB_SRK_TABLE_V2_VERSION)]
    #[br(assert(version == AHAB_SRK_TABLE_V2_VERSION, "Incompatible srk table version"))]
    version: u8,
    pub records: [SrkRecordMldsa; 4],
}

impl BinaryLen for SrkTableMldsa {
    fn binary_len(&self) -> usize {
        4 + self
            .records
            .iter()
            .map(|r| r.crypto_params.len() + 12)
            .sum::<usize>()
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SrkData {
    #[brw(pad_before(1))]
    #[bw(calc = self.binary_len() as u16 )]
    len: u16,
    // TAG_AHAB_SRK_DATA
    #[brw(magic = 0x5Du8)]
    #[brw(pad_after(3))]
    pub srk_id: u8,
    #[br(count = len - 8 ) ]
    pub data: Vec<u8>,
}

impl BinaryLen for SrkData {
    fn binary_len(&self) -> usize {
        self.data.len() + 8
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Eq, PartialEq)]
pub struct SrkArrayHybrid {
    // 0x0
    pub version: u8,
    // length 0xD00
    pub len: u16,
    //TAG_AHAB_SRK_ARRAY
    pub tag: u8,
    #[brw(pad_after(3))]
    // Seemingly always two for the hybrid signing?
    pub count: u8,
    pub srk_table_ecsda: SrkTableEcsdaP384,
    pub srk_data_ecdsa: SrkData,
    pub srk_table_mldsa: SrkTableMldsa,
    pub srk_data_mldsa: SrkData,
}

impl BinaryLen for SrkArrayHybrid {
    fn binary_len(&self) -> usize {
        0xD00
    }
}

#[binrw]
#[brw(little)]
struct MbiHeader {
    total_len: u32,
    #[br(temp, assert(image_type == 0 || image_type == 4, "unexpected image type {image_type:#x}"))]
    #[bw(calc = 4u32)]
    image_type: u32,
    container_offset: u32,
    #[bw(seek_before = SeekFrom::Current(8))]
    exec_addr: u32,
}

#[derive(Error, Debug)]
pub enum PatchError {
    #[error("total length overflow")]
    LengthOverFlow,
    #[error("binary write error")]
    BinError(
        #[source]
        #[from]
        binrw::error::Error,
    ),
}

pub fn patch_mbi_payload_header(
    payload: &mut [u8],
    container_offset: u32,
    container_len: u32,
    exec_addr: u32,
) -> Result<(), PatchError> {
    let total_len = container_offset
        .checked_add(container_len)
        .ok_or(PatchError::LengthOverFlow)?;
    let mut cursor = Cursor::new(payload);
    cursor.set_position(MBI_HDR_OFF_TOTAL_LEN as u64);
    // Read to check if we are not just writing to some random unexpected data.
    MbiHeader::read(&mut cursor)?;
    cursor.set_position(MBI_HDR_OFF_TOTAL_LEN as u64);
    MbiHeader {
        total_len,
        container_offset,
        exec_addr,
    }
    .write(&mut cursor)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn srk_data() {
        let pub_key_raw = [0xA, 0xB, 0xC, 0xD];
        let expected = [0, 12, 0, 93, 0, 0, 0, 0, 10, 11, 12, 13];
        println!("Expected: {expected:?}");
        let srk_data = SrkData {
            srk_id: 0x0,
            data: Vec::from(pub_key_raw),
        }
        .to_vec()
        .expect("Failed to serialize");
        assert_eq!(srk_data, expected);
    }
}
