#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // TODO(10.3): wire to graph::CorrelationGraph once 10.3 lands
    panic!("stub");
});
