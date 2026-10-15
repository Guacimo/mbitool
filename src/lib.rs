use crate::mbi::{
    AHAB_CONTAINER_VERSION, AHAB_KEY_SIZE_P384, AHAB_SIGBLK_VERSION, AhabContainer,
    AhabContainerFlags, AhabHash, BinaryLen, ECC_P384_COORD_LEN, HashAlgorithm, ImageEntry,
    SignAlgorithm, SignatureBlock, SignatureContainer, SrkArrayHybrid, SrkData, SrkRecordEcsda,
    SrkRecordMldsa, SrkTableEcsdaP384, SrkTableMldsa, TAG_AHAB_CONTAINER_HEADER,
    TAG_AHAB_SRK_ARRAY, ToVec, hash,
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
    pub data: Vec<u8>,
    pub load_address: u64,
    pub entry_point: u64,
    pub image_type: ImageType,
    pub hash_type: HashAlgorithm,
}

pub struct SrkTable {
    pub flag_ca: bool,
    pub srk_array: [Vec<u8>; 4],
}

/// Build an MBI container from the given images and other parameters.
///
/// The first image must be an executable and its entry point is used as the overal execution address.
pub fn build_hybrid_mbi_container(
    mut images: Vec<Image>,
    srk_set: SrkSet,
    used_srk_id: u8,
    srk_ecdsa: [Vec<u8>; 4], // The contents of the .pub files
    srk_mldsa: [Vec<u8>; 4], // The contents of the .pem files
    fuse_version: u8,
    image_version: u16,
    exec_addr: u32,
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

    let srk_data_ecdsa = SrkData {
        srk_id: used_srk_id,
        data: srk_ecdsa[used_srk_id as usize].clone(),
    };
    let srk_data_mldsa = SrkData {
        srk_id: used_srk_id,
        data: srk_mldsa[used_srk_id as usize].clone(),
    };

    let srk_table_ecsda = SrkTableEcsdaP384 {
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

    let srk_table_mldsa = SrkTableMldsa {
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

    let srk_array = SrkArrayHybrid {
        version: 0x0,
        len: 0xD00,
        tag: TAG_AHAB_SRK_ARRAY,
        count: 2,
        srk_table_ecsda,
        srk_data_ecdsa,
        srk_table_mldsa,
        srk_data_mldsa,
    };

    let signature_block = SignatureBlock {
        version: AHAB_SIGBLK_VERSION,
        cert_off: 0x0,
        srk_off: 0x10,
        srk_array,
        signatures: [
            SignatureContainer {
                signature: Vec::from([00; 0x64]), // Unsigned
            },
            SignatureContainer {
                signature: Vec::from([00; 0x1217]), // Unsigned
            },
        ],
    };

    let container_offset = images.iter().map(|img| img.data.len()).sum::<usize>() as u32;
    let container_len = 16usize + (128usize * images.len()) + signature_block.binary_len();

    if let Some(image) = images.get_mut(0) {
        crate::mbi::patch_mbi_payload_header(
            &mut image.data,
            container_offset,
            container_len as u32,
            exec_addr,
        )
        .expect("Failed to patch mbi payload header");
    }

    let container = AhabContainer {
        version: AHAB_CONTAINER_VERSION,
        flags: AhabContainerFlags::new()
            .with_used_srk_id(used_srk_id)
            .with_srk_set(srk_set as _),
        fuse_version,
        image_version,
        images: images
            .into_iter()
            .map(|image| ImageEntry {
                offset: 0,
                size: image.data.len().try_into().unwrap(),
                load_address: image.load_address,
                entry_point: image.entry_point,
                flags: 0x15,
                hash: hash(&image.data, HashAlgorithm::Sha384),
            })
            .collect(),
        signature_block,
        tag: TAG_AHAB_CONTAINER_HEADER,
    };

    container.to_vec().unwrap()
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
