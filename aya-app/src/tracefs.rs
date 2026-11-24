//! Tracepoint `format` parsing.
//!
//! Tracefs exposes each tracepoint's binary layout in
//! `/sys/kernel/tracing/events/<category>/<name>/format`. Example line:
//!
//! ```text
//! field:char prev_comm[16];    offset:8;    size:16;    signed:1;
//! ```
//!
//! We parse the field name, offset, and size, then validate the sizes we rely
//! on. Anything unexpected is a hard error: emitting events with a wrong offset
//! would produce plausible-looking garbage, which is worse than refusing to
//! start.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use aya_app_common::TracepointOffsets;

/// One field from a tracepoint format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub offset: u32,
    pub size: u32,
}

/// Parsed field table for one tracepoint.
#[derive(Debug, Default)]
pub struct Format {
    fields: HashMap<String, Field>,
}

impl Format {
    /// Reads and parses `<tracefs>/events/<category>/<name>/format`.
    pub fn load(tracefs: &Path, category: &str, name: &str) -> anyhow::Result<Self> {
        let path = tracefs
            .join("events")
            .join(category)
            .join(name)
            .join("format");
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read tracepoint format {}", path.display()))?;
        Self::parse(&content)
            .with_context(|| format!("failed to parse tracepoint format {}", path.display()))
    }

    /// Parses the format file contents. Kept separate for unit testing.
    pub fn parse(content: &str) -> anyhow::Result<Self> {
        let mut fields = HashMap::new();

        for line in content.lines() {
            let Some(field_pos) = line.find("field:") else {
                continue;
            };
            let rest = &line[field_pos + "field:".len()..];
            let declaration = rest.split(';').next().unwrap_or("").trim();
            let Some(raw_name) = declaration.split_whitespace().last() else {
                continue;
            };
            // `char prev_comm[16]` -> `prev_comm`; `const char *name` -> `name`.
            let name = raw_name
                .trim_start_matches('*')
                .split('[')
                .next()
                .unwrap_or(raw_name)
                .trim();
            if name.is_empty() {
                continue;
            }

            let Some(offset) = attribute(rest, "offset:") else {
                continue;
            };
            let Some(size) = attribute(rest, "size:") else {
                continue;
            };

            fields.insert(name.to_string(), Field { offset, size });
        }

        if fields.is_empty() {
            bail!("no fields found in tracepoint format");
        }
        Ok(Self { fields })
    }

    /// Returns a field or a descriptive error.
    pub fn field(&self, name: &str) -> anyhow::Result<Field> {
        self.fields
            .get(name)
            .copied()
            .with_context(|| format!("tracepoint format does not contain field `{name}`"))
    }

    /// Requires a field with an exact size and returns its offset.
    pub fn require(&self, name: &str, expected_size: u32) -> anyhow::Result<u32> {
        let field = self.field(name)?;
        if field.size != expected_size {
            bail!(
                "field `{name}` has size {}, expected {expected_size}; kernel tracepoint layout is incompatible",
                field.size
            );
        }
        Ok(field.offset)
    }

    /// Requires a field of at least `min_size` bytes and returns its offset.
    ///
    /// Used for text arrays whose length has grown over kernel versions (for
    /// example `block_rq_issue`'s `rwbs`: 8 bytes in older kernels, 10 in
    /// newer ones). The event structure keeps only the first 8 bytes.
    pub fn require_min(&self, name: &str, min_size: u32) -> anyhow::Result<u32> {
        let field = self.field(name)?;
        if field.size < min_size {
            bail!(
                "field `{name}` has size {}, expected at least {min_size}; kernel tracepoint layout is incompatible",
                field.size
            );
        }
        Ok(field.offset)
    }

    /// Requires a field whose size is one of `expected_sizes`.
    pub fn require_one_of(&self, name: &str, expected_sizes: &[u32]) -> anyhow::Result<Field> {
        let field = self.field(name)?;
        if !expected_sizes.contains(&field.size) {
            bail!(
                "field `{name}` has size {}, expected one of {expected_sizes:?}",
                field.size
            );
        }
        Ok(field)
    }

    /// Returns a field only when it exists with the expected size.
    pub fn optional(&self, name: &str, expected_size: u32) -> Option<Field> {
        self.fields
            .get(name)
            .copied()
            .filter(|field| field.size == expected_size)
    }
}

/// Extracts `key:<number>` from a format line.
fn attribute(line: &str, key: &str) -> Option<u32> {
    let pos = line.find(key)?;
    let rest = &line[pos + key.len()..];
    rest.split(';').next()?.trim().parse().ok()
}

/// Locates tracefs, optionally using an explicit path.
pub fn find_tracefs(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        ensure_tracefs(path)?;
        return Ok(path.to_path_buf());
    }

    for candidate in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let path = Path::new(candidate);
        if path.join("events").is_dir() {
            return Ok(path.to_path_buf());
        }
    }

    bail!(
        "tracefs not found. Mount it with `mount -t tracefs tracefs /sys/kernel/tracing` \
         or `mount -t debugfs debugfs /sys/kernel/debug` (aya looks in both standard locations)"
    )
}

fn ensure_tracefs(path: &Path) -> anyhow::Result<()> {
    if !path.join("events").is_dir() {
        bail!(
            "{} does not look like tracefs (missing events/ directory)",
            path.display()
        );
    }
    Ok(())
}

/// Fills the `sched_switch` half of the offsets structure.
pub fn fill_sched_offsets(offsets: &mut TracepointOffsets, tracefs: &Path) -> anyhow::Result<()> {
    let format = Format::load(tracefs, "sched", "sched_switch")?;

    offsets.sched_prev_comm = format.require("prev_comm", 16)?;
    offsets.sched_prev_pid = format.require("prev_pid", 4)?;
    offsets.sched_prev_prio = format.require("prev_prio", 4)?;
    let prev_state = format.require_one_of("prev_state", &[4, 8])?;
    offsets.sched_prev_state = prev_state.offset;
    offsets.sched_prev_state_size = prev_state.size;
    offsets.sched_next_comm = format.require("next_comm", 16)?;
    offsets.sched_next_pid = format.require("next_pid", 4)?;
    offsets.sched_next_prio = format.require("next_prio", 4)?;
    offsets.sched_valid = 1;
    Ok(())
}

/// Fills the `block_rq_issue` half of the offsets structure.
///
/// `bytes` is optional: it is missing on some older kernels, and the BPF
/// program then reports 0 instead of failing to attach.
pub fn fill_block_offsets(offsets: &mut TracepointOffsets, tracefs: &Path) -> anyhow::Result<()> {
    let format = Format::load(tracefs, "block", "block_rq_issue")?;

    offsets.block_dev = format.require("dev", 4)?;
    offsets.block_sector = format.require("sector", 8)?;
    offsets.block_nr_sector = format.require("nr_sector", 4)?;
    offsets.block_bytes = format
        .optional("bytes", 4)
        .map(|field| field.offset)
        .unwrap_or(0);
    offsets.block_rwbs = format.require_min("rwbs", 8)?;
    offsets.block_comm = format.require("comm", 16)?;
    offsets.block_valid = 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inline_field_lines() {
        let content = r#"
name: sched_switch
ID: 314
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:char prev_comm[16];	offset:8;	size:16;	signed:1;
	field:pid_t prev_pid;	offset:24;	size:4;	signed:1;
	field:long prev_state;	offset:32;	size:8;	signed:1;
"#;
        let format = Format::parse(content).unwrap();
        assert_eq!(
            format.field("prev_comm").unwrap(),
            Field {
                offset: 8,
                size: 16
            }
        );
        assert_eq!(format.require("prev_pid", 4).unwrap(), 24);
        assert!(format.require("prev_pid", 8).is_err());
        assert_eq!(
            format.require_one_of("prev_state", &[4, 8]).unwrap().size,
            8
        );
    }

    #[test]
    fn rejects_missing_field() {
        let content = "field:int a; offset:8; size:4; signed:1;\n";
        let format = Format::parse(content).unwrap();
        assert!(format.field("b").is_err());
    }

    #[test]
    fn accepts_grown_text_array() {
        // Linux 6.18's block_rq_issue has `char rwbs[10]`; only the first 8
        // bytes are copied into the event, but parsing must not reject it.
        let content = "field:char rwbs[10]; offset:34; size:10; signed:0;\n";
        let format = Format::parse(content).unwrap();
        assert_eq!(format.require_min("rwbs", 8).unwrap(), 34);
        assert!(format.require("rwbs", 8).is_err());
    }

    #[test]
    fn optional_field_is_ignored_on_size_mismatch() {
        let content = "field:u32 bytes; offset:12; size:8; signed:0;\n";
        let format = Format::parse(content).unwrap();
        assert!(format.optional("bytes", 4).is_none());
    }
}
