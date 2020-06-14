
use std::sync::Arc;
use std::io::{ BufReader };
use std::net::{ SocketAddr };
use futures::channel::oneshot::{ self, Sender, Receiver };

use async_std::sync::{ RwLock };
use hyper::service::{service_fn}; 
use hyper::server::conn::Http;
use hyper::{Body, Method, Request, Response};
use http::header;

use tokio;
use tokio::net::{ TcpListener };
use tokio_rustls::rustls::{ Certificate, NoClientAuth, ServerConfig };
use tokio_rustls::rustls::internal::pemfile::{ certs, rsa_private_keys, pkcs8_private_keys };
use tokio_rustls::TlsAcceptor;
use rustls::{ProtocolVersion, ResolvesServerCertUsingSNI, TLSError, sign::{ CertifiedKey, RSASigningKey, SigningKey}};

use crate::http_proxy;
use crate::web_server;
use crate::data::{ self, SslCertificate, user };
use crate::auth;
use crate::api_server;

#[derive(Clone)]
pub struct ListeningInfo {
    pub http_port : u16,
    pub https_port : u16,
    pub is_https_enabled : bool,
}

impl ListeningInfo {
    fn default() -> ListeningInfo {
        ListeningInfo {
            http_port : 80,
            https_port : 443,
            is_https_enabled : false,
        }
    }
}

lazy_static! {
    static ref TLS_ACCEPTOR: RwLock<TlsAcceptor> = RwLock::new(TlsAcceptor::from(Arc::new(ServerConfig::new(NoClientAuth::new()))));
    static ref LISTENING_INFO : RwLock<ListeningInfo> = RwLock::new(ListeningInfo::default());
    static ref SIGNALER : RwLock<Option<Sender<()>>> = RwLock::new(None);
}

pub async fn get_listening_info() -> ListeningInfo {
    LISTENING_INFO.read().await.clone()
}

pub async fn run(http_port:u16, https_port : u16) -> Result<(), hyper::error::Error> {


    let http_addr = format!("0.0.0.0:{}", http_port);
    let https_addr = format!("0.0.0.0:{}", https_port);
    
    let (sender, receiver) = oneshot::channel::<()>();
    
    {
        let mut signaler = SIGNALER.write().await;
        *signaler = Some(sender);
    }
    {
        let mut listening_info = LISTENING_INFO.write().await;
        *listening_info = ListeningInfo {
            http_port : http_port,
            https_port : https_port,
            is_https_enabled : false,
        };
    }

    reload_tls_config().await;
 
    futures::join!( run_http(http_addr), run_https(https_addr, receiver));
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
        {
            let mut tls_acceptor = TLS_ACCEPTOR.write().await;
            *tls_acceptor = TlsAcceptor::from(Arc::new(config));
        }
        info!("HTTPS loaded {} certificates", count);

        let listening_info = get_listening_info().await;
        if !listening_info.is_https_enabled {
            let mut signaler = SIGNALER.write().await;
            if let Some(sender) = signaler.take() {
                let _ = sender.send(());
            }
        }
    }  

}





async fn run_http(addr : String) {
    let mut listener = TcpListener::bind(&addr).await.expect(&format!("HTTP failed to bind {}", &addr));
    info!("HTTP is listening on {}", addr);

    loop {
        let result = listener.accept().await;
        if let Err(e) = result {
            error!("Unable to accept HTTPS connection. {}", e);
            continue;
        } else if let Ok((socket, client_addr)) = result  {
            tokio::spawn(async move {
                let result = Http::new()
                    .http1_only(true)
                    .serve_connection(socket, service_fn(move |req| handle(req, client_addr)))
                    .with_upgrades()
                    .await;
                if let Err(e) = result {
                    info!("hyper serve_connection({}) failed for HTTP. {}", client_addr.ip(), e);
                }
            });
            
        }
    }
}


async fn run_https(addr : String, receiver : Receiver<()>) {
    let mut listener = TcpListener::bind(&addr).await.expect(&format!("HTTPS failed to bind {}", &addr));

    receiver.await.expect("HTTPS failed to start because it cannot receive signal.");
    info!("HTTPS is listening on {}", addr);

    {
        let mut listening_info = LISTENING_INFO.write().await;
        listening_info.is_https_enabled = true;
    }

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
                            info!("hyper serve_connection({}) failed for HTTPS. {}", client_addr.ip(), e);
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
    if req.method() == &Method::TRACE { // TRACE method to test credentials
        let header = req.headers().get(header::AUTHORIZATION);
        if let Some(user) = auth::basic_authenticate(header) {
            if user.level >= user::USER_LEVEL_NORMAL {
                return api_server::handle(req, client_addr).await;
            }
        }
    }

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


