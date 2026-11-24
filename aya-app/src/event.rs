//! Ring-buffer event stream.
//!
//! Aya 0.16 deliberately does not ship a Tokio integration. `RingBuf`
//! implements `AsFd`, and the documented pattern is to wrap it in
//! `tokio::io::unix::AsyncFd`. `for_each` polls readiness, drains every queued
//! record, then clears the readiness flag.
//!
//! Events are decoded with `ptr::read_unaligned` after a length check. The ring
//! buffer guarantees 8-byte alignment, but using `read_unaligned` keeps the
//! helper sound even if a future event type needs stricter alignment than the
//! ring buffer provides.

use std::{io, mem::size_of, ptr};

use anyhow::Context as _;
use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
};
use tokio::io::{Interest, unix::AsyncFd};

/// A readiness-driven ring buffer.
pub struct EventStream {
    fd: AsyncFd<RingBuf<MapData>>,
}

impl EventStream {
    /// Takes the named ring buffer map out of `bpf` and registers it with Tokio.
    pub fn take(bpf: &mut Ebpf, name: &str) -> anyhow::Result<Self> {
        let map = bpf
            .take_map(name)
            .with_context(|| format!("BPF map `{name}` is missing from the object"))?;
        let ring =
            RingBuf::try_from(map).with_context(|| format!("map `{name}` is not a ring buffer"))?;
        // SAFETY: `ring` owns its file descriptor for as long as `AsyncFd`
        // owns `ring`, and nothing else closes it. We only wait for
        // readability; `RingBuf::next` is non-blocking.
        let fd = unsafe { AsyncFd::register_with_interest(ring, Interest::READABLE) }
            .with_context(|| format!("failed to register {name} with Tokio"))?;
        Ok(Self { fd })
    }

    /// Drains every currently available record, invoking `on_event` for each.
    ///
    /// Returns when the ring buffer is empty. The caller is expected to call
    /// this from a `tokio::select!` loop; it is level-triggered by `AsyncFd`.
    pub async fn for_each<T>(&mut self, mut on_event: impl FnMut(T)) -> io::Result<()>
    where
        T: Copy,
    {
        let mut guard = self.fd.readable_mut().await?;
        while let Some(item) = guard.get_inner_mut().next() {
            if let Some(event) = decode::<T>(&item) {
                on_event(event);
            }
        }
        guard.clear_ready();
        Ok(())
    }
}

/// Decodes one fixed-size event, returning `None` for a short record.
pub fn decode<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: length checked; `read_unaligned` permits any alignment. Every
    // event type is `repr(C)` and fully initialised by the eBPF program.
    Some(unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}
