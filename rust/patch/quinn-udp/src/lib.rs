//! quinn-udp — Shadow-compatible fallback-only build
//!
//! This is a vendored replacement for quinn-udp 0.5.14 that always uses the
//! simple fallback UDP path (send_to/recv_from_vectored) instead of the
//! Linux-optimized unix.rs path. This is required for Shadow network simulator
//! compatibility, since Shadow does not fully emulate sendmsg/recvmsg cmsg,
//! GRO/GSO, or ECN socket options.
//!
//! See: https://shadow.github.io/
#![warn(unreachable_pub)]
#![warn(clippy::use_self)]

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

// Always use fallback — no unix.rs, no windows.rs, no cmsg
#[path = "fallback.rs"]
mod imp;

#[allow(unused_imports, unused_macros)]
mod log {
    #[cfg(all(feature = "direct-log", not(feature = "tracing")))]
    pub(crate) use log::{debug, error, info, trace, warn};

    #[cfg(feature = "tracing")]
    pub(crate) use tracing::{debug, error, info, trace, warn};

    #[cfg(not(any(feature = "direct-log", feature = "tracing")))]
    mod no_op {
        macro_rules! trace    ( ($($tt:tt)*) => {{}} );
        macro_rules! debug    ( ($($tt:tt)*) => {{}} );
        macro_rules! info     ( ($($tt:tt)*) => {{}} );
        macro_rules! log_warn ( ($($tt:tt)*) => {{}} );
        macro_rules! error    ( ($($tt:tt)*) => {{}} );

        pub(crate) use {debug, error, info, log_warn as warn, trace};
    }

    #[cfg(not(any(feature = "direct-log", feature = "tracing")))]
    pub(crate) use no_op::*;
}

pub use imp::UdpSocketState;

/// Number of UDP packets to send/receive at a time
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;

/// Metadata for a single buffer filled with bytes received from the network
#[derive(Debug, Copy, Clone)]
pub struct RecvMeta {
    pub addr: SocketAddr,
    pub len: usize,
    pub stride: usize,
    pub ecn: Option<EcnCodepoint>,
    pub dst_ip: Option<IpAddr>,
}

impl Default for RecvMeta {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }
    }
}

/// An outgoing packet
#[derive(Debug, Clone)]
pub struct Transmit<'a> {
    pub destination: SocketAddr,
    pub ecn: Option<EcnCodepoint>,
    pub contents: &'a [u8],
    pub segment_size: Option<usize>,
    pub src_ip: Option<IpAddr>,
}

/// Log at most 1 IO error per minute
const IO_ERROR_LOG_INTERVAL: Duration = std::time::Duration::from_secs(60);

#[cfg(any(feature = "tracing", feature = "direct-log"))]
fn log_sendmsg_error(
    last_send_error: &Mutex<Instant>,
    err: impl core::fmt::Debug,
    transmit: &Transmit,
) {
    let now = Instant::now();
    let last_send_error = &mut *last_send_error.lock().expect("poisoned lock");
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        log::warn!(
            "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, ecn: {:?}, len: {:?}, segment_size: {:?} }}",
            err,
            transmit.destination,
            transmit.src_ip,
            transmit.ecn,
            transmit.contents.len(),
            transmit.segment_size
        );
    }
}

#[cfg(not(any(feature = "tracing", feature = "direct-log")))]
fn log_sendmsg_error(_: &Mutex<Instant>, _: impl core::fmt::Debug, _: &Transmit) {}

/// A borrowed UDP socket
pub struct UdpSockRef<'a>(socket2::SockRef<'a>);

#[cfg(unix)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsFd,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

#[cfg(windows)]
impl<'s, S> From<&'s S> for UdpSockRef<'s>
where
    S: AsSocket,
{
    fn from(socket: &'s S) -> Self {
        Self(socket.into())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    Ect0 = 0b10,
    Ect1 = 0b01,
    Ce = 0b11,
}

impl EcnCodepoint {
    pub fn from_bits(x: u8) -> Option<Self> {
        use EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }
}
