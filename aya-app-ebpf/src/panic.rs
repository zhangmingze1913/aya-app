//! Minimal panic handler shared by all scenario bins.
//!
//! eBPF has no unwinding and no libc. Reaching this handler means the verifier
//! accepted an impossible path; halt rather than emit an invalid stream.

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
