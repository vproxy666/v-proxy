

use std::path::Path;
use std::fs;
use std::io;


use rusqlite::{Error as SqlError};

mod accessor;
pub mod config;
pub mod user;

pub use user::User;


// Set data dir
pub fn initialize(data_dir : &Path) -> Result<(), io::Error> {
    fs::create_dir_all(data_dir)?;

    let db_path = data_dir.join("db_20200212.sqlite"); // if database schema makes breaking change, update the file name 
    accessor::initialize(db_path.to_str().unwrap())?;


    Ok(())
}

pub struct SslCertificate {
    pub id: u32,
    pub domain: String,
    pub certificate: Vec<u8>,
    pub key: Vec<u8>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
}

impl SslCertificate {
    pub fn new(domain:String, certificate: Vec<u8>, key: Vec<u8>) -> SslCertificate {
        SslCertificate{
            id : 0,
            domain : domain,
            certificate : certificate,
            key : key,
            subject : None,
            issuer : None,
            valid_from : None,
            valid_to : None,
        }
    }
} 

pub fn get_ssl_certificates() -> Result<Vec<SslCertificate>, SqlError> {
    accessor::get_ssl_certificates()
}

pub fn add_ssl_certificates(ssl_certificate : &SslCertificate) -> Result<(), SqlError>  {
    accessor::add_ssl_certificates(ssl_certificate)
}

pub fn del_ssl_certificate(id : i32) -> Result<(), SqlError> {
    accessor::del_ssl_certificate(id)
}


pub fn save_ssl_certificates(ssl_certificate : &SslCertificate) -> Result<(), SqlError>  {
    accessor::save_ssl_certificates(ssl_certificate)
}





