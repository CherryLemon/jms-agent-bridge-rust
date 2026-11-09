//! One process-wide rustls crypto provider.
//!
//! `reqwest` is built with the `rustls-no-provider` feature so no C toolchain-heavy
//! provider is compiled in; the ring provider is installed once, before any TLS
//! client is created. Installing it more than once is harmless.

use std::sync::Once;

static PROVIDER: Once = Once::new();

pub fn install_default_provider() {
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
