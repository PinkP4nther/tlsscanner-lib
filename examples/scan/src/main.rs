// Import TLS Scanner 
use tlsscanner::TlsScanner;

// Import Instant for getting elapsed time
use std::time::Instant;

fn main() {

    // Start counting time
    let counter = Instant::now();

    // Scan host and store results
    // (TCP Host, TCP Port, CN)
    let scan_results = TlsScanner("google.com", "443", "google.com").scan();

    // Get elapsed time.
    let elapsed_seconds = counter.elapsed().as_millis();

    // Print results
    println!("[+] SSL 2.0: {}", scan_results.sslv2);
    println!("[+] SSL 3.0: {}", scan_results.sslv3);
    println!("[+] TLS 1.0: {}", scan_results.tls10);
    println!("[+] TLS 1.1: {}", scan_results.tls11);
    println!("[+] TLS 1.2: {}", scan_results.tls12);
    println!("[+] TLS 1.3: {}", scan_results.tls13);

    // Print elapsed time.
    println!("[+] Time elapsed: {} ms.", elapsed_seconds);
}

