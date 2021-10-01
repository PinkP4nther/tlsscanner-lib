use openssl::ssl::{
    SslConnector,
    SslMethod,
    SslOptions,
    SslVerifyMode,
    HandshakeError,
};
use std::net::TcpStream;
use std::fmt;

pub enum TLSDetect {
    Enabled,
    Disabled,
    Failed,
}

pub struct ScanResult {
    pub sslv2: TLSDetect,
    pub sslv3: TLSDetect,
    pub tls10: TLSDetect,
    pub tls11: TLSDetect,
    pub tls12: TLSDetect,
    pub tls13: TLSDetect,
}

pub struct TlsScanner(
    pub &'static str, /* TCP Host */
    pub &'static str, /* TCP Port */
    pub &'static str, /* Certificate CN Host */
);

mod tlsscanner;