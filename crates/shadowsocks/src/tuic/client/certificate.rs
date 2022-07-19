use rustls::{Certificate, RootCertStore};
use rustls_pemfile::Item;
use std::{
    fs::{self, File},
    io,
};

pub fn load_certificates(files: &Vec<String>) -> io::Result<RootCertStore> {
    let mut certs = RootCertStore::empty();

    for file in files {
        let mut file = io::BufReader::new(File::open(file)?);

        while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
            if let Item::X509Certificate(cert) = item {
                certs
                    .add(&Certificate(cert))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: {}", e)))?;
            }
        }
    }

    if certs.is_empty() {
        for file in files {
            certs
                .add(&Certificate(fs::read(file)?))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: {}", e)))?;
        }
    }

    for cert in rustls_native_certs::load_native_certs()? {
        certs
            .add(&Certificate(cert.0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("load_certifications: native: {}", e)))?;
    }

    Ok(certs)
}
