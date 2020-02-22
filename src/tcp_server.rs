
use std::sync::Arc;
use std::io::{ BufReader };
use std::net::{ SocketAddr };

use async_std::sync::{ RwLock };
use hyper::service::{service_fn}; 
use hyper::server::conn::Http;
use hyper::{Body, Request, Response};

use tokio;
use tokio::net::{ TcpListener };
use tokio_rustls::rustls::{ Certificate, NoClientAuth, ServerConfig };
use tokio_rustls::rustls::internal::pemfile::{ certs, rsa_private_keys, pkcs8_private_keys };
use tokio_rustls::TlsAcceptor;
use rustls::{ProtocolVersion, ResolvesServerCertUsingSNI, TLSError, sign::{ CertifiedKey, RSASigningKey, SigningKey}};

use crate::http_proxy;
use crate::web_server;
use crate::data::{ self, SslCertificate };


lazy_static! {
    static ref TLS_ACCEPTOR: RwLock<TlsAcceptor> = RwLock::new(TlsAcceptor::from(Arc::new(ServerConfig::new(NoClientAuth::new()))));
    static ref HTTP_PORT: RwLock<u16> = RwLock::new(0);
    static ref HTTPS_PORT: RwLock<u16> = RwLock::new(0);
}

pub async fn get_listening_ports() -> (u16, u16) {
    let http_port = HTTP_PORT.read().await;
    let https_port = HTTPS_PORT.read().await;
    (http_port.clone(),  https_port.clone())
}

pub async fn run(http_port:u16, https_port : u16) -> Result<(), hyper::error::Error> {
    {
        let mut port = HTTP_PORT.write().await;
        *port = http_port;
    }

    {
        let mut port = HTTPS_PORT.write().await;
        *port = https_port;
    }

    reload_tls_config().await;

    let addr_str = format!("0.0.0.0:{}", http_port);
    let addr = addr_str.parse::<SocketAddr>().expect(&format!("Unable to parse address {}", addr_str));

    let http_listener = TcpListener::bind(&addr).await.expect(&format!("HTTP failed to bind {}", addr_str));
    info!("HTTP is listening on {}", addr_str);

    let addr_str = format!("0.0.0.0:{}", https_port);
    let addr = addr_str.parse::<SocketAddr>().expect(&format!("Unable to parse address {}", addr_str));

    let https_listener = TcpListener::bind(&addr).await.expect(&format!("HTTPS failed to bind {}", addr_str));
    info!("HTTPS is listening on {}", addr_str);

 
    futures::join!( run_http(http_listener), run_https(https_listener));
    Ok(())
}

async fn run_http(mut listener : TcpListener) {
    loop {
        let result = listener.accept().await;
        if let Err(e) = result {
            error!("Unable to accept HTTP connection. {}", e);
            continue;
        } else if let Ok((socket, client_addr)) = result  {
            tokio::spawn(async move {
                let result = Http::new()
                            .http1_only(true)
                            .serve_connection(socket, service_fn(move |req| handle(req, client_addr)))
                            .with_upgrades()
                            .await;
                        if let Err(e) = result {
                            info!("hyper serve_connection({}) failed. {}", client_addr, e);
                        }
            });
        }
    }
}


async fn run_https(mut listener : TcpListener) {
    loop {
        let result = listener.accept().await;
        if let Err(e) = result {
            error!("Unable to accept HTTPS connection. {}", e);
            continue;
        } else if let Ok((socket, client_addr)) = result  {
            tokio::spawn(async move {
                let tls_acceptor = TLS_ACCEPTOR.read().await.clone();
                match tls_acceptor.accept(socket).await {
                    Ok(stream) => {
                        let result = Http::new()
                            .http1_only(true)
                            .serve_connection(stream, service_fn(move |req| handle(req, client_addr)))
                            .with_upgrades()
                            .await;
                        if let Err(e) = result {
                            info!("hyper serve_connection({}) failed. {}", client_addr, e);
                        }
                    },
                    Err(e) => {
                        error!("TLS hardshake failed. {:?}", e);
                    }
                }
            });
        }
    }
}

async fn handle(mut req: Request<Body>, client_addr : SocketAddr) -> Result<Response<Body>, hyper::Error> {
    if web_server::url_rewrite(&mut req) {
        web_server::handle(req, client_addr).await
    } else {
        http_proxy::handle(req, client_addr).await
    }
    
}






fn load_ssl_certs(rd : &[u8]) -> Option<Vec<Certificate>> {
    if let Ok(certificates) = certs(&mut BufReader::new(rd)) {
        return Some(certificates);
    }
    None
}


fn load_signing_key(rd : &[u8]) -> Option<impl SigningKey> {

    if let Ok(keys) = rsa_private_keys(&mut BufReader::new(rd)) {
        for key in keys {
            if let Ok(signing_key) = RSASigningKey::new(&key) {
                return Some(signing_key);
            }
        }
    }

    if let Ok(keys) = pkcs8_private_keys(&mut BufReader::new(rd)) {
        for key in keys {
            if let Ok(signing_key) = RSASigningKey::new(&key) {
                return Some(signing_key);
            }
        }
    }

    None
}



fn add_to_resolver(resolver : &mut ResolvesServerCertUsingSNI, ssl_certificate : &SslCertificate) -> Result<(), TLSError> {
    let ssl_key = match load_signing_key(&ssl_certificate.key) {
        Some(k) => k,
        None => return Err(TLSError::General("No private key can be loaded.".to_string())),
    };
    let ssl_certs = match load_ssl_certs(&ssl_certificate.certificate) {
        Some(c) => c,
        None => return Err(TLSError::General("No certificate can be loaded.".to_string())),
    };

    let certified_key = CertifiedKey::new(ssl_certs, Arc::new(Box::new(ssl_key)));
    resolver.add(&ssl_certificate.domain, certified_key)
}


pub fn test_ssl_certificate(ssl_certificate : &SslCertificate) -> Result<(), TLSError> {
    let mut resolver = ResolvesServerCertUsingSNI::new();
    add_to_resolver(&mut resolver, ssl_certificate)?;
    Ok(())
}


pub async fn reload_tls_config() {

    let ssl_certificates = match data::get_ssl_certificates() {
        Ok(c) => c,
        Err(e) => {
            error!("get_ssl_certificates() failed. {:?} - {}", e, e);
            return;
        }
    };

    let mut resolver = ResolvesServerCertUsingSNI::new();

    let mut count : i32 = 0;
    for ssl_certificate in ssl_certificates{
        if let Err(e) = add_to_resolver( &mut resolver, &ssl_certificate) {
            error!("Unable to load certificates for {}. {:?} - {}", &ssl_certificate.domain, e, e);
        } else {
            count += 1;
        }
    }

    if count == 0 {
        warn!("No certificate is loaded. HTTPS cannot be enabled");
    } else {
        let mut config = ServerConfig::new(NoClientAuth::new());
        config.cert_resolver = Arc::new(resolver);
        config.versions = vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_1];
        let mut tls_acceptor = TLS_ACCEPTOR.write().await;
        *tls_acceptor = TlsAcceptor::from(Arc::new(config));
        info!("HTTPS loaded {} certificates", count);
    }

    
}


