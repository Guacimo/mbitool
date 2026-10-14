use crate::mbi::HashAlgorithm;

pub mod mbi;
pub mod original_code;

/// Which super root key is used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrkSet {
    /// Provided by the OEM (which is you, not NXP)
    Oem = 2,
    /// Provided by NXP
    Nxp = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    CrcCheck = 1,
    Executable = 3,
    TzData = 5,
}

pub struct Image {
    pub image: Vec<u8>,
    pub load_address: u32,
    pub entry_point: u32,
    pub image_type: ImageType,
    pub hash_type: HashAlgorithm,
    pub version: u32,
}

pub struct SrkTable {
    pub flag_ca: bool,
    pub srk_array: [Vec<u8>; 4],
}

/// Build an MBI container from the given images and other parameters.
///
/// The first image must be an executable and its entry point is used as the overal execution address.
pub fn build_mbi_container(
    images: Vec<Image>,
    srk_set: SrkSet,
    used_srk_id: u8,
    srk_ecdsa: [Vec<u8>; 4], // The contents of the .pub files
    srk_mldsa: [Vec<u8>; 4], // The contents of the .pem files
) -> Vec<u8> {
    assert!(!images.is_empty(), "At least one image must be provided");
    assert_eq!(
        images[0].image_type,
        ImageType::Executable,
        "First image must be an executable"
    );
    assert_eq!(srk_set, SrkSet::Oem, "Only OEM SRK is supported now");
    assert!(
        srk_ecdsa.iter().all(|vec| vec.len() == 96),
        "All ecdsa SRKs must be 96 bytes"
    );
    assert!(
        srk_mldsa.iter().all(|vec| vec.len() == 1952),
        "All mldsa SRKs must be 96 bytes"
    );
    assert!(
        used_srk_id < 4,
        "`used_srk_id` must be in the range of 0..=3"
    );

    todo!()
}
