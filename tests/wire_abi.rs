use sentinel_wire::{decode, encode_to_wire, VersionedTelemetryFrame, MAGIC, VERSION, WIRE_SIZE};
use crc32c::crc32c;

const CANONICAL_HEX_VECTOR: &str = "650000000000000015cd853dfe9c9717efcdab1032547698cdcccc3dcdcc4cbe9a99993ecdccccbe0000003f9a9919bf0000603fd4c3b2a17f5edcb153410101";

fn canonical_frame() -> VersionedTelemetryFrame {
    VersionedTelemetryFrame {
        sequence_id: 101,
        timestamp_ns: 1_700_000_000_123_456_789,
        device_id_hash: 0x9876_5432_10AB_CDEF,
        metrics: [0.1, -0.2, 0.3, -0.4, 0.5, -0.6],
        anomaly_score: 0.875,
        nonce: 0xA1B2C3D4,
        crc32c: 0,
        magic: MAGIC,
        version: VERSION,
        flags: 0x01,
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn canonical_vector_is_exactly_64_bytes_and_roundtrips() {
    assert_eq!(CANONICAL_HEX_VECTOR.len(), 128);
    let bytes = hex_to_bytes(CANONICAL_HEX_VECTOR);
    assert_eq!(bytes.len(), WIRE_SIZE);

    let expected_crc = 0xB1DC5E7Fu32;
    assert_eq!(crc32c(&bytes[..56]), expected_crc);
    assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), expected_crc);

    let frame = decode(&bytes).expect("canonical vector must decode");
    assert_eq!(frame.sequence_id, 101);
    assert_eq!(frame.timestamp_ns, 1_700_000_000_123_456_789);
    assert_eq!(frame.device_id_hash, 0x9876_5432_10AB_CDEF);
    assert_eq!(frame.metrics, [0.1, -0.2, 0.3, -0.4, 0.5, -0.6]);
    assert_eq!(frame.anomaly_score, 0.875);
    assert_eq!(frame.nonce, 0xA1B2C3D4);
    assert_eq!(frame.magic, MAGIC);
    assert_eq!(frame.version, VERSION);
    assert_eq!(frame.flags, 0x01);
    assert_eq!(encode_to_wire(&frame).to_vec(), bytes);
}

#[test]
fn every_crc_covered_byte_mutation_is_rejected() {
    let bytes = hex_to_bytes(CANONICAL_HEX_VECTOR);
    for index in 0..56 {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 0x01;
        assert!(decode(&corrupted).is_err(), "byte {index} mutation must be rejected");
    }
}

#[test]
fn magic_and_version_mutations_are_rejected_even_with_recomputed_crc() {
    let bytes = hex_to_bytes(CANONICAL_HEX_VECTOR);

    let mut bad_magic = bytes.clone();
    bad_magic[60] ^= 0x01;
    bad_magic[56..60].copy_from_slice(&crc32c(&bad_magic[..56]).to_le_bytes());
    assert!(decode(&bad_magic).is_err());

    let mut bad_version = bytes;
    bad_version[62] ^= 0x01;
    bad_version[56..60].copy_from_slice(&crc32c(&bad_version[..56]).to_le_bytes());
    assert!(decode(&bad_version).is_err());
}

#[test]
fn invalid_lengths_are_rejected() {
    assert!(decode(&[0u8; 63]).is_err());
    assert!(decode(&[0u8; 65]).is_err());
}

#[test]
fn non_finite_floats_are_rejected() {
    let bytes = hex_to_bytes(CANONICAL_HEX_VECTOR);

    for index in 0..6 {
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut mutated = bytes.clone();
            mutated[24 + index * 4..28 + index * 4].copy_from_slice(&value.to_le_bytes());
            assert!(decode(&mutated).is_err(), "metric {index} non-finite value must be rejected");
        }
    }

    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut mutated = bytes.clone();
        mutated[48..52].copy_from_slice(&value.to_le_bytes());
        assert!(decode(&mutated).is_err(), "anomaly_score non-finite value must be rejected");
    }
}

#[test]
fn serialization_is_deterministic() {
    let frame = canonical_frame();
    let first = encode_to_wire(&frame);
    for _ in 0..100 {
        assert_eq!(encode_to_wire(&frame), first);
    }
}
