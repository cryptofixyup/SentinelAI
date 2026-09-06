use crc32c::crc32c;
use std::cell::UnsafeCell;
use std::mem::{align_of, size_of};

pub const WIRE_SIZE: usize = 64;
pub const HEADER_SIZE: usize = 56;
pub const MAGIC: u16 = 0x4153;
pub const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct VersionedTelemetryFrame {
    pub sequence_id: u64,
    pub timestamp_ns: u64,
    pub device_id_hash: u64,
    pub metrics: [f32; 6],
    pub anomaly_score: f32,
    pub nonce: u32,
    pub crc32c: u32,
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
}

const _: () = assert!(size_of::<VersionedTelemetryFrame>() == 64);
const _: () = assert!(align_of::<VersionedTelemetryFrame>() == 8);

#[repr(C, align(64))]
pub struct RingSlot<T> {
    pub value: UnsafeCell<T>,
}

const _: () = assert!(size_of::<RingSlot<VersionedTelemetryFrame>>() == 64);
const _: () = assert!(align_of::<RingSlot<VersionedTelemetryFrame>>() == 64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength,
    NonFiniteMetric,
    NonFiniteAnomalyScore,
    InvalidMagic,
    InvalidVersion,
    InvalidCrc,
}

pub fn decode(bytes: &[u8]) -> Result<VersionedTelemetryFrame, DecodeError> {
    if bytes.len() != WIRE_SIZE {
        return Err(DecodeError::InvalidLength);
    }

    let metrics = std::array::from_fn(|i| f32::from_le_bytes(bytes[24 + i * 4..28 + i * 4].try_into().unwrap()));
    if metrics.iter().any(|v| !v.is_finite()) {
        return Err(DecodeError::NonFiniteMetric);
    }

    let anomaly_score = f32::from_le_bytes(bytes[48..52].try_into().unwrap());
    if !anomaly_score.is_finite() {
        return Err(DecodeError::NonFiniteAnomalyScore);
    }

    if u16::from_le_bytes(bytes[60..62].try_into().unwrap()) != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    if bytes[62] != VERSION {
        return Err(DecodeError::InvalidVersion);
    }
    if crc32c(&bytes[..HEADER_SIZE]) != u32::from_le_bytes(bytes[56..60].try_into().unwrap()) {
        return Err(DecodeError::InvalidCrc);
    }

    Ok(VersionedTelemetryFrame {
        sequence_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        timestamp_ns: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        device_id_hash: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        metrics,
        anomaly_score,
        nonce: u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
        crc32c: u32::from_le_bytes(bytes[56..60].try_into().unwrap()),
        magic: u16::from_le_bytes(bytes[60..62].try_into().unwrap()),
        version: bytes[62],
        flags: bytes[63],
    })
}

pub fn encode_to_wire(frame: &VersionedTelemetryFrame) -> [u8; WIRE_SIZE] {
    assert!(frame.metrics.iter().all(|v| v.is_finite()));
    assert!(frame.anomaly_score.is_finite());

    let mut bytes = [0u8; WIRE_SIZE];
    bytes[0..8].copy_from_slice(&frame.sequence_id.to_le_bytes());
    bytes[8..16].copy_from_slice(&frame.timestamp_ns.to_le_bytes());
    bytes[16..24].copy_from_slice(&frame.device_id_hash.to_le_bytes());
    for (i, metric) in frame.metrics.iter().enumerate() {
        bytes[24 + i * 4..28 + i * 4].copy_from_slice(&metric.to_le_bytes());
    }
    bytes[48..52].copy_from_slice(&frame.anomaly_score.to_le_bytes());
    bytes[52..56].copy_from_slice(&frame.nonce.to_le_bytes());
    let crc = crc32c(&bytes[..HEADER_SIZE]);
    bytes[56..60].copy_from_slice(&crc.to_le_bytes());
    bytes[60..62].copy_from_slice(&MAGIC.to_le_bytes());
    bytes[62] = VERSION;
    bytes[63] = frame.flags;
    bytes
}
