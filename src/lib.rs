use std::marker::PhantomData;

use crate::mbi::{
    AHAB_CONTAINER_VERSION, AHAB_KEY_SIZE_P384, AHAB_SIGBLK_VERSION, AhabContainer,
    AhabContainerFlags, AhabHash, BinaryLen, ECC_P384_COORD_LEN, HashAlgorithm, ImageEntry,
    SignAlgorithm, SignatureBlock, SignatureContainer, SrkArrayHybrid, SrkData, SrkRecordEcsda,
    SrkRecordMldsa, SrkTableEcsdaP384, SrkTableMldsa, TAG_AHAB_CONTAINER_HEADER,
    TAG_AHAB_SRK_ARRAY, ToVec, hash,
};

mod mbi;

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

pub struct Image<'d> {
    /// The bin data of the image
    pub data: &'d mut [u8],
    /// The address of the image in flash
    pub flash_address: u32,
    /// Variable the ROM looks at
    pub load_address: u64,
    /// Variable the ROM looks at
    pub entry_point: u64,
    pub image_type: ImageType,
    pub hash_type: HashAlgorithm,
}

pub struct SignConfig {
    pub srk_set: SrkSet,
    /// The index of the srk that's used to as the srk data for this container
    pub used_srk_id: u8,
    /// The contents of the .pub files
    pub srk_ecdsa: [Vec<u8>; 4],
    /// The contents of the .pem files
    pub srk_mldsa: [Vec<u8>; 4],
}

pub struct Unsigned;
pub struct Signed;

/// Struct to build the bytes of the MBI container
///
/// - First use [Self::build] to build it. We'll have an unsigned container then
/// - Then get the [Self::bytes_to_sign] and sign them
/// - Once signed, insert the signatures with [Self::insert_signatures]
/// - When done, the bytes of the container can be obtained with [Self::to_bytes]
pub struct MbiContainer<T> {
    container: AhabContainer,
    _state: PhantomData<T>,
}

impl MbiContainer<Unsigned> {
    /// Build an unsigned MBI container from the given images and other parameters.
    ///
    /// The first image must be an executable and its entry point is used as the overal execution address.
    pub fn build(
        mut images: Vec<Image<'_>>,
        container_address: u32,
        sign_config: SignConfig,
        fuse_version: u8,
        image_version: u16,
        exec_addr: u32, // Should be 0 for XIP images
    ) -> Self {
        assert!(!images.is_empty(), "At least one image must be provided");
        assert_eq!(
            images[0].image_type,
            ImageType::Executable,
            "First image must be an executable"
        );
        assert_eq!(
            sign_config.srk_set,
            SrkSet::Oem,
            "Only OEM SRK is supported now"
        );
        assert!(
            sign_config.srk_ecdsa.iter().all(|vec| vec.len() == 96),
            "All ecdsa SRKs must be 96 bytes"
        );
        assert!(
            sign_config.srk_mldsa.iter().all(|vec| vec.len() == 1952),
            "All mldsa SRKs must be 96 bytes"
        );
        assert!(
            sign_config.used_srk_id < 4,
            "`used_srk_id` must be in the range of 0..=3"
        );
        assert!(
            container_address > images[0].flash_address,
            "Container must be placed at a higher address than the primary image"
        );

        let srk_data_ecdsa = SrkData {
            srk_id: sign_config.used_srk_id,
            data: sign_config.srk_ecdsa[sign_config.used_srk_id as usize].clone(),
        };
        let srk_data_mldsa = SrkData {
            srk_id: sign_config.used_srk_id,
            data: sign_config.srk_mldsa[sign_config.used_srk_id as usize].clone(),
        };

        let srk_table_ecsda = SrkTableEcsdaP384 {
            records: {
                let [e0, e1, e2, e3] = sign_config.srk_ecdsa;
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
                let [e0, e1, e2, e3] = sign_config.srk_mldsa;
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

        let container = AhabContainer {
            version: AHAB_CONTAINER_VERSION,
            flags: AhabContainerFlags::new()
                .with_used_srk_id(sign_config.used_srk_id)
                .with_srk_set(sign_config.srk_set as _),
            fuse_version,
            image_version,
            images: images
                .iter()
                .map(|image| ImageEntry {
                    offset: 0,
                    size: image.data.len().try_into().unwrap(),
                    load_address: image.load_address,
                    entry_point: image.entry_point,
                    flags: 0x15,
                    hash: hash(image.data, HashAlgorithm::Sha384),
                })
                .collect(),
            signature_block,
            tag: TAG_AHAB_CONTAINER_HEADER,
        };

        let container_offset = container_address - images[0].flash_address;
        // Patch the vector table of the first image (which we know is an executable)
        // This will tell the ROM where to find the container
        crate::mbi::patch_mbi_payload_header(
            images[0].data,
            container_offset,
            container.binary_len() as u32,
            exec_addr,
        )
        .expect("Failed to patch mbi payload header");

        MbiContainer {
            container,
            _state: Default::default(),
        }
    }

    /// Get the bytes that need to be signed
    pub fn bytes_to_sign(&self) -> Vec<u8> {
        // Get all of the container bytes
        let mut container_bytes = self.container.to_vec().unwrap();
        // Only keep the bytes up to the signature block
        container_bytes.truncate(self.container.signature_block_offset() as usize);
        container_bytes
    }

    pub fn insert_signatures(
        mut self,
        signature_0: Vec<u8>,
        signature_1: Vec<u8>,
    ) -> MbiContainer<Signed> {
        self.container.signature_block.signatures[0].signature = signature_0;
        self.container.signature_block.signatures[1].signature = signature_1;

        MbiContainer {
            container: self.container,
            _state: Default::default(),
        }
    }
}

impl MbiContainer<Signed> {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.container.to_vec().unwrap()
    }
}

fn srk_ecdsa_to_record(index: u8, data: Vec<u8>) -> SrkRecordEcsda {
    SrkRecordEcsda {
        sign_algorithm: SignAlgorithm::Ecdsa,
        hash_algorithm: HashAlgorithm::Sha384,
        key_size: AHAB_KEY_SIZE_P384,
        p_len_x: ECC_P384_COORD_LEN as u16,
        p_len_y: ECC_P384_COORD_LEN as u16,
        crypto_params: SrkData {
            srk_id: index,
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
            srk_id: index,
            data,
        }
        .hash(HashAlgorithm::Sha384)
        .unwrap()
        .into(),
    }
}
