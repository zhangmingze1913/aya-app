//! A tiny, deterministic userspace target for the uprobe examples.
//!
//! The functions are exported with the C ABI and `#[unsafe(no_mangle)]` so the
//! symbol name in the ELF file is exactly `demo_handle_request` /
//! `demo_slow_query`. `#[inline(never)]` keeps the functions as real call
//! targets in release builds.
//!
//! Build and run:
//!
//! ```text
//! cargo build --release -p aya-app-demo
//! ./target/release/aya-app-demo 200
//! ```
//!
//! Then attach:
//!
//! ```text
//! sudo -E ./target/release/aya-app uprobe \
//!     --binary ./target/release/aya-app-demo \
//!     --symbol demo_handle_request
//! ```

use std::{
    env,
    ffi::{CStr, c_char},
    thread,
    time::Duration,
};

/// Simulated request handler.
///
/// # Arguments
///
/// * `request_id` — monotonic request number (uprobe reads this from arg 0).
/// * `path` — NUL-terminated request path (uprobe reads this from arg 1).
///
/// The artificial sleep makes the uretprobe latency visible. A real service
/// would do work here instead.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn demo_handle_request(request_id: u64, path: *const c_char) {
    let path = if path.is_null() {
        "<null>".to_string()
    } else {
        // SAFETY: the caller passes a NUL-terminated `CString` that stays alive
        // for the duration of this call.
        unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .into_owned()
    };

    // Deterministic 2..8 ms of "work" so the latency histogram has spread.
    let work_ms = 2 + (request_id % 7);
    thread::sleep(Duration::from_millis(work_ms));

    println!("[demo] request_id={request_id:<6} work={work_ms}ms path={path}");
}

/// A slower function that can be used as a second uprobe target.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn demo_slow_query(ms: u64) {
    thread::sleep(Duration::from_millis(ms.min(1_000)));
    println!("[demo] slow_query ms={ms}");
}

fn main() {
    let mut args = env::args().skip(1);
    let iterations: u64 = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(200);
    let gap_ms: u64 = args
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);

    println!("[demo] starting: iterations={iterations} gap={gap_ms}ms; Ctrl-C to stop");

    for request_id in 0..iterations {
        let path = std::ffi::CString::new(format!("/api/v1/orders/{request_id}"))
            .expect("generated paths never contain NUL");
        demo_handle_request(request_id, path.as_ptr());

        if request_id % 50 == 0 {
            demo_slow_query(10 + request_id % 20);
        }

        thread::sleep(Duration::from_millis(gap_ms));
    }

    println!("[demo] done");
}
