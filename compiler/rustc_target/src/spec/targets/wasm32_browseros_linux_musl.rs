//! The `wasm32-browseros-linux-musl` target: programs for BrowserOS, a Linux-like OS that runs
//! WebAssembly processes in the browser.
//!
//! BrowserOS's libc is musl with an `arch/wasm32` whose ABI is that of riscv32 (the libc crate
//! uses its riscv32 definitions for this target), and the kernel is called through Linux (riscv32,
//! asm-generic) system call numbers. Programs are linked the way C programs for
//! `wasm32-unknown-linux-musl` are on BrowserOS: by the C driver (`cc`), as position-independent
//! executables and shared libraries that load `libc.so` dynamically. The driver and its linker
//! (clang and wasm-ld on BrowserOS, `browser-cc` and `browser-ld` from `@progate/browser-ld`
//! elsewhere) take the ELF linker's arguments, so this target links like other Linux targets.

use crate::spec::{
    BinaryFormat, Cc, LinkSelfContainedDefault, LinkerFlavor, Lld, PanicStrategy, RelocModel, RelroLevel,
    Target, TargetMetadata, TargetOptions, TlsModel, base,
};

pub(crate) fn target() -> Target {
    let mut options = TargetOptions { vendor: "browseros".into(), ..base::linux_musl::opts() };

    options.families = crate::spec::cvs!["unix", "wasm"];
    options.is_like_wasm = true;
    options.binary_format = BinaryFormat::Wasm;

    // Link with the C driver, like the C programs of BrowserOS. The driver brings the crt objects,
    // libc and compiler-rt, so nothing is self-contained.
    options.linker = Some("cc".into());
    options.linker_flavor = LinkerFlavor::Gnu(Cc::Yes, Lld::No);
    options.link_self_contained = LinkSelfContainedDefault::False;
    options.pre_link_objects_self_contained = Default::default();
    options.post_link_objects_self_contained = Default::default();

    // Position-independent executables that load libc.so, and shared libraries (`dylib`,
    // `cdylib` and `proc-macro`) that BrowserOS's dynamic loader opens.
    options.relocation_model = RelocModel::Pic;
    options.position_independent_executables = true;
    options.dynamic_linking = true;
    options.crt_static_default = false;
    options.crt_static_respected = true;
    options.exe_suffix = "".into();
    // The crt1 of BrowserOS calls `main(argc, argv)` by its WebAssembly name, as clang names it.
    options.entry_name = "__main_argc_argv".into();
    options.dll_prefix = "lib".into();
    options.dll_suffix = ".so".into();

    // The world with threads: shared memory, and `pthread_create` from musl. `-pthread` makes the
    // driver link the threaded libraries (`usr/lib/wasm32-linux-musl-threads`) with shared memory.
    options.add_pre_link_args(LinkerFlavor::Gnu(Cc::Yes, Lld::No), &["-pthread"]);
    options.features = "+atomics,+bulk-memory,+mutable-globals,+sign-ext".into();
    options.singlethread = false;
    options.max_atomic_width = Some(64);
    options.has_thread_local = true;
    options.tls_model = TlsModel::LocalExec;

    // Unwinding with WebAssembly exceptions comes later; abort for now.
    options.panic_strategy = PanicStrategy::Abort;
    options.default_uwtable = false;
    options.eh_frame_header = false;

    // WebAssembly has no RELRO (data segments are not mapped read-only): pass no -z relro option at all.
    options.relro_level = RelroLevel::None;
    options.emit_debug_gdb_scripts = false;
    options.generate_arange_section = false;

    Target {
        llvm_target: "wasm32-unknown-linux-musl".into(),
        metadata: TargetMetadata {
            description: Some("WebAssembly for BrowserOS (Linux system calls, musl)".into()),
            tier: Some(3),
            host_tools: Some(false),
            std: Some(true),
        },
        pointer_width: 32,
        data_layout: "e-m:e-p:32:32-p10:8:8-p20:8:8-i64:64-i128:128-n32:64-S128-ni:1:10:20".into(),
        arch: crate::spec::Arch::Wasm32,
        options,
    }
}
