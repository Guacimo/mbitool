use crate::mbi::{
    AHAB_KEY_SIZE_P384, AhabHash, ECC_P384_COORD_LEN, HashAlgorithm, SignAlgorithm, SrkData,
    SrkRecordEcsda, SrkRecordMldsa, SrkTableEcsdaP384, SrkTableMldsa,
};

mod mbi;
mod original_code;

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
pub fn build_hybrid_mbi_container(
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

    let srk_ecdsa_table = SrkTableEcsdaP384 {
        records: {
            let [e0, e1, e2, e3] = srk_ecdsa;
            [
                srk_ecdsa_to_record(0, e0),
                srk_ecdsa_to_record(1, e1),
                srk_ecdsa_to_record(2, e2),
                srk_ecdsa_to_record(3, e3),
            ]
        },
    };

    let srk_mldsa_table = SrkTableMldsa {
        records: {
            let [e0, e1, e2, e3] = srk_mldsa;
            [
                srk_mldsa_to_record(0, e0),
                srk_mldsa_to_record(1, e1),
                srk_mldsa_to_record(2, e2),
                srk_mldsa_to_record(3, e3),
            ]
        },
    };

    todo!()
}

fn srk_ecdsa_to_record(index: u8, data: Vec<u8>) -> SrkRecordEcsda {
    SrkRecordEcsda {
        sign_algorithm: SignAlgorithm::Ecdsa,
        hash_algorithm: HashAlgorithm::Sha384,
        key_size: AHAB_KEY_SIZE_P384,
        p_len_x: ECC_P384_COORD_LEN as u16,
        p_len_y: ECC_P384_COORD_LEN as u16,
        crypto_params: SrkData {
            srk_id: index as u8,
            data,
        }
        .hash(HashAlgorithm::Sha384)
        .unwrap()
        .into(),
    }
}

fn srk_mldsa_to_record(index: u8, data: Vec<u8>) -> SrkRecordMldsa {
    SrkRecordMldsa {
        sign_algorithm: SignAlgorithm::Mldsa,
        hash_algorithm: HashAlgorithm::Sha384,
        key_size: 0x09,
        p_len: data.len().try_into().unwrap(),
        crypto_params: SrkData {
            srk_id: index as u8,
            data,
        }
        .hash(HashAlgorithm::Sha384)
        .unwrap()
        .into(),
    }
}
