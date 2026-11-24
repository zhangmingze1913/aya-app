#![no_std]
#![no_main]
#![allow(dead_code)]

#[path = "../panic.rs"]
mod panic;
#[path = "../programs/probe.rs"]
mod probe;
#[path = "../programs/uprobe.rs"]
mod uprobe;
#[path = "../utils.rs"]
mod utils;
