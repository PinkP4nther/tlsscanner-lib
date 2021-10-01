use crate::*;

impl TlsScanner {

    pub fn scan(&self) -> ScanResult {

        ScanResult {
            sslv2: self.tls_version_detect(SslOptions::NO_SSL_MASK & !SslOptions::NO_SSLV2),
            sslv3: self.tls_version_detect(SslOptions::NO_SSL_MASK & !SslOptions::NO_SSLV3),
            tls10: self.tls_version_detect(SslOptions::NO_SSL_MASK & !SslOptions::NO_TLSV1),
            tls11: self.tls_version_detect(SslOptions::NO_SSL_MASK & !SslOptions::NO_TLSV1_1),
            tls12: self.tls_version_detect(SslOptions::NO_SSL_MASK & !SslOptions::NO_TLSV1_2),
            tls13: self.tls_version_detect(SslOptions::NO_SSL_MASK & !SslOptions::NO_TLSV1_3),
        }
    }
    
    fn tls_version_detect(&self, version: SslOptions) -> TLSDetect {
    
        let mut ssl_builder = SslConnector::builder(SslMethod::tls()).unwrap();
        ssl_builder.set_options(version);
        ssl_builder.set_verify(SslVerifyMode::NONE);
        let connector = ssl_builder.build();

        let tcp_host = format!("{}:{}", self.0, self.1);
        let stream = TcpStream::connect(tcp_host).unwrap();
    
        match connector.connect(self.2, stream) {
            Ok(_) => TLSDetect::Enabled,
            Err(e) => {
                if let HandshakeError::Failure(hse) = e {
                    if let Some(ssle) = hse.error().ssl_error() {
                        for error in ssle.errors() {
                            if error.code() == 337539263 {
                                return TLSDetect::Disabled;
                            }
                        }
                    }
                    TLSDetect::Failed
                } else {
                    TLSDetect::Failed
                }
            },
        }
    }
}

impl TLSDetect {

    pub fn as_str(&self) -> &'static str {
        match self {
            TLSDetect::Enabled => "Enabled",
            TLSDetect::Disabled => "Disabled",
            TLSDetect::Failed => "Failed",
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            TLSDetect::Enabled => 1,
            TLSDetect::Disabled => 0,
            TLSDetect::Failed => 2,
        }
    }
}

impl fmt::Display for TLSDetect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TLSDetect::Enabled => write!(f, "Enabled"),
            TLSDetect::Disabled => write!(f, "Disabled"),
            TLSDetect::Failed => write!(f, "Failed"),
        }
    }
}