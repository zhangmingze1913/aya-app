#![no_std]
#![no_main]
#![allow(dead_code)]

#[path = "../programs/kprobe.rs"]
mod kprobe;
#[path = "../panic.rs"]
mod panic;
#[path = "../programs/probe.rs"]
mod probe;
#[path = "../utils.rs"]
mod utils;
