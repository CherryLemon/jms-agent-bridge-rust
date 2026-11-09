//! Transport ownership: pooled SSH connections, shell sessions and drain-before-replace.

pub mod recovery;
pub mod rsync;
pub mod session;
pub mod ssh;

pub use recovery::{ConnectionRecovery, Lease, Phase};
pub use rsync::{relay_main, RsyncRelay};
pub use session::{
    exec_end_marker, exec_packet, exec_start_marker, new_nonce, ready_marker, ready_packet,
    terminal_packet, CaptureResult, ShellSession,
};
pub use ssh::{ChannelShell, ShellEvent, SshConnection, SshPool};
