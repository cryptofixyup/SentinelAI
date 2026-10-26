use sentinel_core::{EntropyWindow, SentinelCore, Signal, ENTROPY_WINDOW};

fn entropy(input: &[u8]) -> u32 {
    let mut window = EntropyWindow::new();
    window.load(input);
    window.shannon_milli_bits()
}

#[test]
fn known_shannon_entropies() {
    assert_eq!(entropy(b""), 0);
    assert_eq!(entropy(&[42; ENTROPY_WINDOW]), 0);
    assert_eq!(entropy(b"abab"), 1000);
    assert_eq!(entropy(b"abcd"), 2000);
    let uniform = core::array::from_fn::<_, ENTROPY_WINDOW, _>(|i| i as u8);
    assert_eq!(entropy(&uniform), 8000);
}

#[test]
fn entropy_matches_independent_floating_point_reference() {
    // Exercise every window length and skewed and near-uniform distributions.
    for len in 1..=ENTROPY_WINDOW {
        for alphabet in [2, 3, 7, 16, 127, 256] {
            let input: Vec<u8> = (0..len).map(|i| (i % alphabet) as u8).collect();
            let mut counts = [0usize; 256];
            for &byte in &input {
                counts[byte as usize] += 1;
            }
            let expected: f64 = counts
                .iter()
                .filter(|&&count| count > 0)
                .map(|&count| {
                    let probability = count as f64 / len as f64;
                    -probability * probability.log2() * 1000.0
                })
                .sum();
            assert!(
                (entropy(&input) as f64 - expected).abs() <= 1.0,
                "length {len}, alphabet {alphabet}: {} versus {expected}",
                entropy(&input)
            );
        }
    }
}

#[test]
fn scan_records_correct_entropy_signals() {
    let mut low = SentinelCore::new();
    low.scan(&[42; ENTROPY_WINDOW]);
    assert_eq!(low.event_count(), 1);
    assert_eq!(low.event(0).unwrap().signal, Signal::LowEntropy);
    let mut high = SentinelCore::new();
    high.scan(&core::array::from_fn::<_, ENTROPY_WINDOW, _>(|i| i as u8));
    assert_eq!(high.event_count(), 1);
    assert_eq!(high.event(0).unwrap().signal, Signal::HighEntropy);
}

#[test]
fn window_reloads_and_bounds_input() {
    let mut window = EntropyWindow::new();
    window.load(&[42; ENTROPY_WINDOW + 1]);
    assert_eq!(window.shannon_milli_bits(), 0);
    window.load(b"abcd");
    assert_eq!(window.shannon_milli_bits(), 2000);
    window.load(b"");
    assert_eq!(window.shannon_milli_bits(), 0);
}
