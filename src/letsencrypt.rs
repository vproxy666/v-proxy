use std::process::Stdio; 
use std::io::{ Error, ErrorKind };
use std::fs::{ self, File };
use std::io::prelude::*;
use std::sync::atomic::{ Ordering, AtomicI32 };

use tokio::{ process::Command};
use regex::Regex;

use crate::tcp_server;
use crate::data;
use crate::data::config;
use crate::misc;



lazy_static! {
    static ref RE_COMMON_NAME: Regex = Regex::new(r"(?:\bCN\s*=\s*)(?P<CN>[^,]+)").unwrap();
    static ref RE_PRIVATE_KEY: Regex = Regex::new(r"\s+(?P<PATH>(/[^\n\s/]+)+/)[^\n\s/]+\.pem\s").unwrap();
    static ref SEMAPHORE: AtomicI32 = AtomicI32::new(0);
}

// Determine if we are waiting request from Let's Encrypt
pub fn is_listening() -> bool {
    SEMAPHORE.load(Ordering::Relaxed) > 0
}

pub async fn request(domain: &str, email : &str) -> Result<(bool, String), Error>{
    SEMAPHORE.fetch_add(10, Ordering::SeqCst);
    let result = call(domain, email).await;
    SEMAPHORE.fetch_sub(10, Ordering::SeqCst);
    result
}

async fn call(domain: &str, email : &str) -> Result<(bool, String), Error>{

    // certbot certonly  --webroot -w /var/lib/letsencrypt/wwww -d domain name
    let mut cmd = Command::new("certbot");

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("certonly")
        .arg("--webroot")
        .arg("-w")
        .arg(config::get_challenge_root())  
        .arg("--email") //Enter email address (used for urgent renewal and security notices)
        .arg(email)
        .arg("-d")
        .arg(domain)
        .arg("--agree-tos")
        .arg("--non-interactive")
        .arg("--preferred-challenges")
        .arg("http-01")
        .arg("--duplicate")
        .kill_on_drop(true);

        

    let output = cmd.output().await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

  

    if stdout.find("Congratulations!").is_some() { // succeeded

        let mut key = vec![];
        let mut cert = vec![];
        if let Some(caps) = RE_PRIVATE_KEY.captures(&stdout) {
            if let Some(path) = caps.name("PATH") {
                let entries = fs::read_dir(path.as_str())?
                    .map(|res| res.map(|e| e.path()))
                    .collect::<Result<Vec<_>, Error>>()?;

                for entry in entries {
                    if let Some(ext) = entry.extension() {
                        if let Some(ext) = ext.to_str() {
                            if ext == "pem" {
                                if let Some(filename) = entry.file_name() {
                                    if let Some(filename) = filename.to_str() {
                                        let filename = filename.to_lowercase();
                                        if filename.starts_with("privkey") {
                                            let mut file = File::open(entry.to_str().unwrap())?;
                                            file.read_to_end(&mut key)?;
                                        } else if filename.starts_with("cert") {
                                            let mut file = File::open(entry.to_str().unwrap())?;
                                            file.read_to_end(&mut cert)?;
                                        }

                                    }
                                }
                            }
                        } // if let Some(ext) = ext.to_str()
                    } // if let Some(ext) = entry.extension()
                }// for entry in entries
            }
        }// if let Some(caps) = RE_PRIVATE_KEY.captures(stdout.as_str()) 

        if key.len() > 0 && cert.len() > 0 {
            import_ssl( domain.to_string(), cert, key).await?;
            return Ok( (true, format!("{}\n\n\n{}", stdout, stderr)) );
        } else {
            return Err(Error::new( ErrorKind::Other, "Certbot executed successfully but cannot find the generated files."));
        }

    }

    Ok( (false, format!("{}\n\n\n{}", stdout, stderr)) )
}


async fn import_ssl(domain:String, certificate: Vec<u8>, key: Vec<u8>) -> Result<(), Error> {
    let mut ssl_certificate = data::SslCertificate::new( domain.to_string(), certificate, key);

    if let Err(e) = tcp_server::test_ssl_certificate(&ssl_certificate) {
        return Err(Error::new( ErrorKind::Other, format!("TLS Error :  {}", e)) );
    }


    match x509_parser::pem::Pem::read(std::io::Cursor::new(&ssl_certificate.certificate)){
        Err(e) => warn!("Unable to parse read X.508 certificate. {:?}", e),
        Ok((pem, _)) => {
            match pem.parse_x509() {
                Err(e) => warn!("Unable to parse X.509 information. {:?}", e),
                Ok(x509) => {
                    if let Some(caps) = RE_COMMON_NAME.captures(&x509.tbs_certificate.subject.to_string()) {
                        if let Some(common_name) = caps.name("CN") {
                            ssl_certificate.subject = Some(common_name.as_str().to_string());
                        }
                    }
                    if let Some(caps) = RE_COMMON_NAME.captures(&x509.tbs_certificate.issuer.to_string()) {
                        if let Some(common_name) = caps.name("CN") {
                            ssl_certificate.issuer = Some(common_name.as_str().to_string());
                        }
                    }
                    ssl_certificate.valid_from = Some(misc::convert_to_rfc3339(&x509.tbs_certificate.validity.not_before));
                    ssl_certificate.valid_to = Some(misc::convert_to_rfc3339(&x509.tbs_certificate.validity.not_after));
                },
            }
        }
    };

    if let Err(e) = data::save_ssl_certificates(&ssl_certificate){
        return Err(Error::new( ErrorKind::Other, format!("save_ssl_certificates failed. {:?}", e))  );
    }


    tcp_server::reload_tls_config().await;

    Ok(())
}