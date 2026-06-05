mod did_cache;
mod error;
mod experiment;
mod fs_util;
mod metrics;
mod model;
mod vc;

use error::DynError;

const STACK_SIZE_BYTES: usize = 32 * 1024 * 1024;

fn main() -> Result<(), DynError> {
    // BBS+ signing and JSON-LD canonicalization build large async state
    // machines. A larger stack keeps Windows dev runs aligned with QEMU/Linux
    // behavior without tripping STATUS_STACK_OVERFLOW.
    std::thread::Builder::new()
        .name("leo-vc-roaming-experiment".to_string())
        .stack_size(STACK_SIZE_BYTES)
        .spawn(|| async_std::task::block_on(experiment::run()))?
        .join()
        .expect("leo-vc-roaming experiment thread panicked")
}
