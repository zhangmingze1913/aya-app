//! Per-CPU statistics readers.
//!
//! All counters in the eBPF programs are `PerCpuArray` values. The kernel
//! returns one value per possible CPU; summing them in userspace gives exact
//! totals without atomics in the hot path. The number of returned slots can be
//! larger than the number of online CPUs, so iterate over whatever the kernel
//! gives us.

use anyhow::Context as _;
use aya::{
    Ebpf, Pod,
    maps::{MapData, PerCpuArray},
};

/// Takes ownership of a per-CPU array from the loaded object.
pub fn take_percpu<T: Pod>(bpf: &mut Ebpf, name: &str) -> anyhow::Result<PerCpuArray<MapData, T>> {
    let map = bpf
        .take_map(name)
        .with_context(|| format!("BPF map `{name}` is missing from the object"))?;
    PerCpuArray::try_from(map)
        .with_context(|| format!("map `{name}` is not a per-CPU array of the expected type"))
}

/// Sums index 0 of a per-CPU array. `merge` folds one CPU's value into `total`.
pub fn sum_percpu<T, F>(map: &PerCpuArray<MapData, T>, mut merge: F) -> anyhow::Result<T>
where
    T: Pod + Copy + Default,
    F: FnMut(&mut T, &T),
{
    let values = map
        .get(&0, 0)
        .context("bpf_map_lookup_elem failed for per-CPU stats")?;
    let mut total = T::default();
    for value in values.iter() {
        merge(&mut total, value);
    }
    Ok(total)
}
