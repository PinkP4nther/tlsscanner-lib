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
        let connector = ssl_builder.build();

        let tcp_host = format!("{}:{}", self.0, self.1);
    
        let stream = TcpStream::connect(tcp_host).unwrap();
    
        match connector.connect(self.2, stream) {
            Ok(_) => TLSDetect::Enabled,
            Err(_) => TLSDetect::Disabled,
        }
    }
}

impl TLSDetect {
    pub fn as_str(&self) -> &'static str {
        if let TLSDetect::Enabled = self {"Enabled"} else {"Disabled"}
    }

    pub fn as_u8(&self) -> u8 {
        if let TLSDetect::Enabled = self {1} else {0}
    }

    pub fn as_bool(&self) -> bool {
        if let TLSDetect::Enabled = self {true} else {false}
    }
}

impl fmt::Display for TLSDetect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let TLSDetect::Enabled = self {write!(f, "Enabled")}
        else {write!(f, "Disabled")}
    }
}