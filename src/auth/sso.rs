//! Hosted-only overlay module. The real implementation lives in the hosted
//! deployment repository; the `hosted` feature cannot be enabled in this
//! crate (see the compile_error guard in lib.rs), so this file is never
//! compiled. It exists because tooling that resolves module paths without
//! cfg evaluation (rustfmt) needs the file to be present.
