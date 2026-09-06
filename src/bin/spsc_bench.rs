use sentinel_wire::{RingSlot, VersionedTelemetryFrame, MAGIC, VERSION};
use std::env;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

const CAPACITY: usize = 1024;
const DEFAULT_MESSAGES: usize = 5_000_000;
const SAMPLE_EVERY: u64 = 1_000;

trait Counters: Send + Sync + 'static {
    fn head(&self) -> &AtomicUsize;
    fn tail(&self) -> &AtomicUsize;
}

struct PackedCounters {
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl Counters for PackedCounters {
    fn head(&self) -> &AtomicUsize { &self.head }
    fn tail(&self) -> &AtomicUsize { &self.tail }
}

#[repr(C, align(64))]
struct CacheLineCounter {
    value: AtomicUsize,
    _padding: [u8; 56],
}

struct AlignedCounters {
    head: CacheLineCounter,
    tail: CacheLineCounter,
}

impl Counters for AlignedCounters {
    fn head(&self) -> &AtomicUsize { &self.head.value }
    fn tail(&self) -> &AtomicUsize { &self.tail.value }
}

struct SpscQueue<C: Counters> {
    slots: Box<[RingSlot<VersionedTelemetryFrame>; CAPACITY]>,
    counters: C,
}

// Safety: exactly one producer writes a slot before publishing head with Release;
// exactly one consumer reads that slot after observing head with Acquire. Each slot
// is reused only after the consumer publishes tail with Release. No slot is accessed
// concurrently by both sides.
unsafe impl<C: Counters> Sync for SpscQueue<C> {}
unsafe impl<C: Counters> Send for SpscQueue<C> {}

impl<C: Counters> SpscQueue<C> {
    fn new(counters: C) -> Self {
        let empty = VersionedTelemetryFrame {
            sequence_id: 0,
            timestamp_ns: 0,
            device_id_hash: 0,
            metrics: [0.0; 6],
            anomaly_score: 0.0,
            nonce: 0,
            crc32c: 0,
            magic: MAGIC,
            version: VERSION,
            flags: 0,
        };
        Self {
            slots: Box::new(std::array::from_fn(|_| RingSlot {
                value: std::cell::UnsafeCell::new(empty),
            })),
            counters,
        }
    }

    #[inline]
    fn push(&self, frame: VersionedTelemetryFrame) {
        loop {
            let head = self.counters.head().load(Ordering::Relaxed);
            let tail = self.counters.tail().load(Ordering::Acquire);
            if head.wrapping_sub(tail) < CAPACITY {
                let index = head % CAPACITY;
                unsafe { *self.slots[index].value.get() = frame; }
                self.counters.head().store(head.wrapping_add(1), Ordering::Release);
                return;
            }
            std::hint::spin_loop();
        }
    }

    #[inline]
    fn pop(&self) -> VersionedTelemetryFrame {
        loop {
            let tail = self.counters.tail().load(Ordering::Relaxed);
            let head = self.counters.head().load(Ordering::Acquire);
            if tail != head {
                let index = tail % CAPACITY;
                let frame = unsafe { *self.slots[index].value.get() };
                self.counters.tail().store(tail.wrapping_add(1), Ordering::Release);
                return frame;
            }
            std::hint::spin_loop();
        }
    }
}

fn canonical_frame(sequence_id: u64, timestamp_ns: u64) -> VersionedTelemetryFrame {
    VersionedTelemetryFrame {
        sequence_id,
        timestamp_ns,
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

fn percentile(sorted: &[u64], p: f64) -> u64 {
    let index = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[index]
}

fn run<C: Counters>(mode: &str, messages: usize, counters: C) {
    let queue = Arc::new(SpscQueue::new(counters));
    let start = Instant::now();
    let producer_start = start;
    let producer_queue = Arc::clone(&queue);
    let consumer_queue = Arc::clone(&queue);

    let producer = thread::spawn(move || {
        for sequence in 0..messages as u64 {
            let timestamp_ns = producer_start.elapsed().as_nanos() as u64;
            producer_queue.push(canonical_frame(sequence, timestamp_ns));
        }
    });

    let consumer = thread::spawn(move || {
        let mut samples = Vec::with_capacity(messages / SAMPLE_EVERY as usize + 1);
        let mut checksum = 0u64;
        for _ in 0..messages {
            let frame = consumer_queue.pop();
            if frame.sequence_id % SAMPLE_EVERY == 0 {
                let now_ns = start.elapsed().as_nanos() as u64;
                samples.push(now_ns.saturating_sub(frame.timestamp_ns));
            }
            checksum = checksum.wrapping_add(frame.sequence_id);
            black_box(frame);
        }
        (samples, checksum)
    });

    producer.join().expect("producer thread panicked");
    let (mut samples, checksum) = consumer.join().expect("consumer thread panicked");
    let elapsed = start.elapsed();
    samples.sort_unstable();

    assert_eq!(checksum, (messages as u64 - 1) * messages as u64 / 2);
    let seconds = elapsed.as_secs_f64();
    let throughput = messages as f64 / seconds;

    println!("mode={mode}");
    println!("messages={messages}");
    println!("elapsed_seconds={seconds:.6}");
    println!("throughput_messages_per_second={throughput:.2}");
    println!("latency_samples={}", samples.len());
    println!("latency_p50_ns={}", percentile(&samples, 0.50));
    println!("latency_p99_ns={}", percentile(&samples, 0.99));
    println!("latency_max_ns={}", samples.last().copied().unwrap_or(0));
}

fn main() {
    let mode = env::var("SPSC_MODE").unwrap_or_else(|_| "aligned".to_string());
    let messages = env::var("SPSC_MESSAGES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MESSAGES);
    assert!(messages > 0, "SPSC_MESSAGES must be positive");

    match mode.as_str() {
        "aligned" => run(&mode, messages, AlignedCounters {
            head: CacheLineCounter { value: AtomicUsize::new(0), _padding: [0; 56] },
            tail: CacheLineCounter { value: AtomicUsize::new(0), _padding: [0; 56] },
        }),
        "packed" => run(&mode, messages, PackedCounters {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }),
        other => panic!("unsupported SPSC_MODE: {other}"),
    }
}
