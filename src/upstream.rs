
use std::{sync::{ RwLock, Arc}, future::Future, pin::Pin, task::{self, Poll}};

use http::header::{ self, HeaderValue };
use http::uri::{ PathAndQuery, Scheme };

use hyper::{service::Service, Uri, Body, Client, Request, Response};
use hyper_rustls::HttpsConnector;
use webpki;
use tokio::net::TcpStream;
use rustls::{
    Certificate, ClientConfig, RootCertStore, ServerCertVerified,
    ServerCertVerifier, TLSError,
};

struct UpstreamServer{
    base_url : String,
    host_and_port : String,
    raw_host : String,
    is_https : bool,
}

impl UpstreamServer {
    fn default() -> UpstreamServer {
        UpstreamServer{
            base_url : "".to_string(),
            host_and_port : "".to_string(),
            raw_host : "".to_string(),
            is_https : false,
        }
    }

    fn from(uri : Uri) -> Option<UpstreamServer> {

        match (uri.scheme(), uri.host(), uri.port()) {
            (Some(scheme), Some(host), Some(port)) => {
                Some(UpstreamServer {
                    base_url : format!("{}://{}:{}{}", scheme, host, port, uri.path().trim_end_matches('/')),
                    host_and_port : format!("{}:{}", host, port),
                    raw_host : host.to_string(),
                    is_https : scheme == &Scheme::HTTPS,
                })
            },
            (Some(scheme), Some(host), None) if scheme == &Scheme::HTTPS => {
                Some(UpstreamServer {
                    base_url : format!("{}://{}{}", scheme, host, uri.path().trim_end_matches('/')),
                    host_and_port : format!("{}:443", host),
                    raw_host : host.to_string(),
                    is_https : scheme == &Scheme::HTTPS,
                })
            },
            (Some(scheme), Some(host), None) if scheme == &Scheme::HTTP => {
                Some(UpstreamServer {
                    base_url : format!("{}://{}{}", scheme, host, uri.path().trim_end_matches('/')),
                    host_and_port : format!("{}:80", host),
                    raw_host : host.to_string(),
                    is_https : scheme == &Scheme::HTTPS,
                })
            },
            _ => {
                error!("Invalid URL : {}", uri);
                None
            }
        }      
    }
}

lazy_static! {
    static ref UPSTREAM_SRV : RwLock<Arc<UpstreamServer>> = RwLock::new(Arc::new(UpstreamServer::default()));
}

pub fn set_uri(uri : Uri) {
    if let Some(srv) = UpstreamServer::from(uri) {
        let mut upstream_srv = UPSTREAM_SRV.write().unwrap();
        *upstream_srv = Arc::new(srv);
    }
}

fn get_server() -> Option<Arc<UpstreamServer>> {
    let srv = UPSTREAM_SRV.read().unwrap().clone();
    if srv.base_url.len() == 0 {
        None
    } else {
        Some(srv)
    }
}




pub async fn request(mut req: Request<Body>) -> Result<Response<Body>, hyper::Error> {

    let target_uri = req.uri();
    let mut path_and_query : String = target_uri.path_and_query().unwrap_or(&PathAndQuery::from_static("/")).to_string();

    if !path_and_query.starts_with("/"){
        path_and_query.insert(0, '/');
    }
    
    let srv = match get_server() {
        Some(s) => s,
        None => {
            let mut resp = Response::new(Body::from("No upstream server in configuration"));
            *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
            return Ok(resp);
        }
    };
    if target_uri.authority().is_none() { // this is a normal request
        let new_uri = format!("{}{}", 
                srv.base_url, 
                path_and_query
            );
        *req.uri_mut() = new_uri.parse().unwrap();
    }

    let headers = req.headers_mut();
    headers.remove(header::PROXY_AUTHORIZATION); // remove PROXY_AUTHORIZATION if exists
    headers.remove(header::HOST);  // remove original HOST http header
    headers.remove(header::ORIGIN);
    headers.remove(header::REFERER);
    if let Ok(new_header) = HeaderValue::from_str(&srv.raw_host) {
        headers.append( header::HOST, new_header);
    } else {
        warn!("Unable to add host {}", &srv.raw_host);
    }
    
   
    let connector = UpstreamConnector{};


    let fu = if srv.is_https {
        let mut config = ClientConfig::new();
        config.dangerous().set_certificate_verifier(Arc::new(NoCertVerification{}));
        Client::builder().build(HttpsConnector::from((connector, config))).request(req)
    } else {
        Client::builder().build(connector).request(req)
    };

    match fu.await {
        Err(e) => {
            let body = format!("Failed to send request to upstream {}\n\n {}", &srv.base_url, e);
            let mut resp = Response::new(Body::from(body));
            *resp.status_mut() = http::StatusCode::BAD_GATEWAY;

            Ok(resp)
        },
        Ok(resp) => {
            Ok(resp)
        }
    }
   
}


struct NoCertVerification;

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        _presented_certs: &[Certificate],
        _dns_name: webpki::DNSNameRef<'_>,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}


#[derive(Clone)]
pub struct UpstreamConnector;

impl Service<Uri> for UpstreamConnector {
    type Response = TcpStream;
    type Error = std::io::Error;

    type Future = Pin<Box<
        dyn Future<Output = Result<Self::Response, Self::Error>> + Send
    >>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        // This connector is always ready, but others might not be.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        if let Some(srv) = get_server() {
            Box::pin(TcpStream::connect(srv.host_and_port.clone()))
        } else {
            Box::pin(TcpStream::connect("0.0.0.0"))
        }
        
    }
}