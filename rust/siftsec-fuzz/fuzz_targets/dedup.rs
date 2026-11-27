#![no_main]
// SPDX-License-Identifier: Apache-2.0
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // TODO(10.2): wire to dedup::FindingIndex once 10.2 lands
    panic!("stub");
});
