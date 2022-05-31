use k8s_openapi::ByteString;

use crate::constants::{CERT_FILENAME, KEY_FILENAME};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::{thread, time};

pub struct CertKeyPair {
    pub cert: String,
    pub key: String,
}

impl CertKeyPair {
    pub fn from_secret(map: &BTreeMap<String, ByteString>) -> Option<CertKeyPair> {
        let cert = match map.get(CERT_FILENAME) {
            Some(data) => match String::from_utf8(data.0.clone()) {
                Ok(data) => data,
                Err(_) => return None,
            },
            None => return None,
        };
        let key = match map.get(KEY_FILENAME) {
            Some(data) => match String::from_utf8(data.0.clone()) {
                Ok(data) => data,
                Err(_) => return None,
            },
            None => return None,
        };
        Some(CertKeyPair { cert, key })
    }
}

pub fn gen_cert(service_name: String, namespace: &str, local_name: Option<String>) -> CertKeyPair {
    let mut params = rcgen::CertificateParams::default();
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName(format!(
            "{}.{}",
            service_name, namespace
        )));
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName(format!(
            "{}.{}.svc",
            service_name, namespace
        )));
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName(format!(
            "{}.{}.svc.cluster.local",
            service_name, namespace
        )));
    if let Some(local_name) = local_name {
        params.subject_alt_names.push(extract_hostname(local_name));
    }
    let cert = rcgen::Certificate::from_params(params).expect("failed to generate certificate");
    let cert_data = cert.serialize_pem().expect("failed to serialize cert");
    let key_data = cert.serialize_private_key_pem();
    CertKeyPair {
        cert: cert_data,
        key: key_data,
    }
}

fn extract_hostname(local_name: String) -> rcgen::SanType {
    let is_ip = local_name.to_lowercase().starts_with("ip:");
    let local_name = local_name.to_lowercase().replace("ip:", "");
    let mut local_name_split = local_name.split(':');
    let hostname = local_name_split
        .next()
        .expect("expected string to have ':'");
    if is_ip {
        rcgen::SanType::IpAddress(hostname.parse().expect("failed to parse IP"))
    } else {
        rcgen::SanType::DnsName(hostname.to_string())
    }
}

pub fn read_cert(cert_dir: String) -> Option<CertKeyPair> {
    let cert_path = Path::new(&cert_dir).join(CERT_FILENAME);
    let key_path = Path::new(&cert_dir).join(KEY_FILENAME);
    if !Path::new(&cert_path).exists() || !Path::new(&key_path).exists() {
        None
    } else {
        let mut cert_file = File::open(cert_path).expect("failed to open cert file");
        let mut cert_data = String::new();
        cert_file
            .read_to_string(&mut cert_data)
            .expect("failed to read cert file");
        let mut key_file = File::open(key_path).expect("failed to open key file");
        let mut key_data = String::new();
        key_file
            .read_to_string(&mut key_data)
            .expect("failed to read key file");
        Some(CertKeyPair {
            cert: cert_data,
            key: key_data,
        })
    }
}

pub fn wait_for_certs(cert_dir: String) -> CertKeyPair {
    let cert_path = Path::new(&cert_dir).join(CERT_FILENAME);
    let key_path = Path::new(&cert_dir).join(KEY_FILENAME);

    let mut counter = 0;

    while !Path::new(&cert_path).exists() || !Path::new(&key_path).exists() && counter < 10 {
        thread::sleep(time::Duration::from_secs(2));
        counter += 1;
    }
    read_cert(cert_dir).expect("failed to read cert")
}
