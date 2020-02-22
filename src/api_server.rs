
use serde_json::json;

use std::net::{ SocketAddr };
use std::io::prelude::*;
use std::collections::HashMap;
use hyper::{Body, Method, Request, Response};
use http::{ StatusCode, header };
use bytes::buf::ext::BufExt;
use regex::Regex;
use rusqlite::{Error as SqlError, ErrorCode};
use x509_parser;
use url::form_urlencoded;
use http::uri::{ Uri, Scheme };


use crate::tcp_server;
use crate::upstream;
use crate::data::{ self, config };


lazy_static! {
    static ref RE_CONTENT_TYPE: Regex = Regex::new(r"(?:multipart/form\-data;\s*boundary\s*=\s*)(?P<boundary>[^\s]+)").unwrap();
    static ref RE_COMMON_NAME: Regex = Regex::new(r"(?:\bCN\s*=\s*)(?P<CN>[^,]+)").unwrap();
}


pub async fn handle(req: Request<Body>, client_addr : SocketAddr) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/api/basic_info") => get_basic_info(&client_addr).await,
        (&Method::POST, "/api/settings") => update_setting(req, &client_addr).await,
        (&Method::GET, "/api/ssl_certificate") => get_ssl_certificates(&client_addr).await,
        (&Method::POST, "/api/ssl_certificate") => add_ssl_certificates(req, &client_addr).await,
        (&Method::DELETE, "/api/ssl_certificate") => del_ssl_certificate(req, &client_addr).await,
        (&Method::GET, "/api/user") => get_users(&client_addr).await,
        (&Method::POST, "/api/user") => save_user(req, &client_addr).await,
        (&Method::DELETE, "/api/user") => del_user(req, &client_addr).await,
        (method, path) => {
            Ok(
                build_error_response(StatusCode::NOT_FOUND
                    , &format!("No handler is found for {} {}", method, path)
                ) 
            )
        }
    }
}


fn build_error_response(status_code : http::StatusCode, error : &str) -> Response<Body> {
    let payload = json!({
        "success": false,
        "message": error
    });
    Response::builder()
        .status(status_code)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(payload.to_string()))
        .unwrap()
}

fn build_success_response(payload : serde_json::value::Value) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(payload.to_string()))
        .unwrap()
    
}


async fn get_basic_info(_client_addr : &SocketAddr) -> Result<Response<Body>, hyper::Error> {
    let (http_port, https_port) = tcp_server::get_listening_ports().await;

    let certs_num = match data::get_ssl_certificates() {
        Ok(vec) => vec.len(),
        Err(_) => 0
    };

    let payload = json!({
        "success": true,
        "http_port": http_port,
        "https_port": https_port,
        "console_path": config::get_console_path(),
        "origin_url": config::get_origin_url(),
        "certificate_num" : certs_num,
        "http_proxy" : config::is_http_proxy_enabled(),
        "https_proxy" : true,
        "disguise_mode" : config::is_disguise_mode_enabled(),
    });
    Ok(build_success_response(payload))
}

async fn update_setting(req: Request<Body>, _client_addr : &SocketAddr) -> Result<Response<Body>, hyper::Error> {

    // Concatenate the body...
    let b = hyper::body::to_bytes(req).await?;
    let params = form_urlencoded::parse(b.as_ref())
        .into_owned()
        .collect::<HashMap<String, String>>();

    if let Some(url) = params.get("origin_url") {

        let upstream_url : Uri = match url.parse() {
            Ok(u) => u,
            Err(_) => return Ok( build_error_response( StatusCode::BAD_REQUEST, "`origin_url` is invalid")),
        };

        if upstream_url.scheme() != Some(&Scheme::HTTP) && upstream_url.scheme() != Some(&Scheme::HTTPS) {
            return Ok( build_error_response( StatusCode::BAD_REQUEST, "Origin url scheme must be HTTP or HTTPS."));
        }
        if upstream_url.host() == None {
            return Ok( build_error_response( StatusCode::BAD_REQUEST, "Origin url host is missing."));
        }

        upstream::set_uri(upstream_url);
        config::set_origin_url(url.as_str());
    };

    if let Some(mode) = params.get("disguise_mode") {
        if let Ok(enabled) = mode.parse::<bool>() {
            config::enable_disguise_mode(enabled);
        }
    }

    if let Some(mode) = params.get("http_proxy") {
        if let Ok(enabled) = mode.parse::<bool>() {
            config::enable_http_proxy(enabled);
        }
    }

    let payload = json!({
        "success": true
    });
    Ok(build_success_response(payload))
}

async fn get_ssl_certificates(_client_addr : &SocketAddr) -> Result<Response<Body>, hyper::Error> {

    let ssl_certificates = match data::get_ssl_certificates() {
        Ok(vec) => vec,
        Err(e) => {
            return Ok( 
                build_error_response( StatusCode::INTERNAL_SERVER_ERROR
                    , &format!("get_ssl_certificates() failed. {:?} - {}", e, e) 
                )
            );
        }
    };

    let mut items = Vec::new();
    for ssl_certificate in ssl_certificates {
        items.push(json!({
            "id": ssl_certificate.id,
            "domain": ssl_certificate.domain,
            "subject": ssl_certificate.subject,
            "issuer": ssl_certificate.issuer,
            "valid_from": ssl_certificate.valid_from,
            "valid_to": ssl_certificate.valid_to,
        }));
    }

    let payload = json!({
        "success": true,
        "items": items
    });
    Ok(build_success_response(payload))
}

async fn del_ssl_certificate(req: Request<Body>, _client_addr : &SocketAddr) -> Result<Response<Body>, hyper::Error> {

    let params = form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>();

    let id : i32 = if let Ok(n) = params.get("id").unwrap_or(&"".to_string()).parse() {
        n
    } else {
        return Ok( build_error_response( StatusCode::BAD_REQUEST, "Missing parameter `id`") )
    };
    
    if let Err(e) = data::del_ssl_certificate(id){
        return Ok( build_error_response( StatusCode::INTERNAL_SERVER_ERROR, &format!("del_ssl_certificate failed. {:?}", e))  );
    }

    tcp_server::reload_tls_config().await;

    let payload = json!({
        "success": true
    });
    Ok(build_success_response(payload))
}

async fn add_ssl_certificates(req: Request<Body>, _client_addr : &SocketAddr) -> Result<Response<Body>, hyper::Error> {
    
    let content_type = match req.headers().get(http::header::CONTENT_TYPE){
        Some(ct) => ct.clone(),
        None => return Ok( build_error_response( StatusCode::BAD_REQUEST, "Invalid `Content-Type` http header") ),
    };
    let whole_body = hyper::body::aggregate(req).await?;
    let reader = whole_body.reader();
    let hyper_request = HyperRequest(content_type, reader);
    let mut form_data = match multipart::server::Multipart::from_request(hyper_request) {
        Err(_) => return Ok( build_error_response( StatusCode::BAD_REQUEST, "Failed to parse multipart form data.") ),
        Ok(form_data) => form_data,
    };

    let mut ssl_cert = Vec::new();
    let mut ssl_key = Vec::new();
    let mut ssl_domain = String::new();
    let _ = form_data.foreach_entry(|mut field| {
        let name = field.headers.name.to_string();
        let _ = match name.as_str() {
            "ssl_cert" => field.data.read_to_end(&mut ssl_cert),
            "ssl_key" => field.data.read_to_end(&mut ssl_key),
            "ssl_domain" => field.data.read_to_string(&mut ssl_domain),
            _ => Ok(0),
        };
        
    });

    if ssl_domain.len() == 0 || ssl_cert.len() == 0 || ssl_key.len() == 0 {
        return Ok( build_error_response( StatusCode::BAD_REQUEST, "Missing parameters")  );
    }
    

    let mut ssl_certificate = data::SslCertificate::new( ssl_domain.clone(), ssl_cert, ssl_key);

    if let Err(e) = tcp_server::test_ssl_certificate(&ssl_certificate) {
        return Ok( build_error_response( StatusCode::BAD_REQUEST, &format!("TLS Error : {:?} - {}", e, e))  );
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
                    ssl_certificate.valid_from = Some(x509.tbs_certificate.validity.not_before.rfc3339().to_string());
                    ssl_certificate.valid_to = Some(x509.tbs_certificate.validity.not_after.rfc3339().to_string());
                },
            }
        }
    };


    match data::add_ssl_certificates(&ssl_certificate){
        Err(SqlError::SqliteFailure(error, _)) if ErrorCode::ConstraintViolation == error.code && error.extended_code == 2067 /* A UNIQUE constraint failed */ => {
            return Ok( build_error_response( StatusCode::CONFLICT, &format!("You cannot add SSL certificate for {} since it already exists.", &ssl_certificate.domain))  );
        },
        Err(e) => {
            return Ok( build_error_response( StatusCode::INTERNAL_SERVER_ERROR, &format!("add_ssl_certificates failed. {:?}", e))  );
        },
        _ => (),
    };


    tcp_server::reload_tls_config().await;

    let payload = json!({
        "success": true
    });
    Ok(build_success_response(payload))
}

struct HyperRequest<T>(
    pub http::HeaderValue,
    pub bytes::buf::ext::Reader<T>
) where T : bytes::Buf;





impl<T> multipart::server::HttpRequest for HyperRequest<T> where T : bytes::Buf
 {
    type Body = bytes::buf::ext::Reader<T>;

    fn multipart_boundary(&self) -> Option<&str> {

        //multipart/form-data; boundary=----WebKitFormBoundary4i6QDXQSYADpZsRZ
        if let Ok(text) = self.0.to_str() {
            if let Some(caps) = RE_CONTENT_TYPE.captures(text) {
                if let Some(boundary) = caps.name("boundary") {
                    return Some(boundary.as_str());
                }
            }
        }
        return None;
    }

    fn body(self) -> Self::Body {
        self.1
    }
}




async fn get_users(_client_addr : &SocketAddr) -> Result<Response<Body>, hyper::Error> {

    let users = match data::user::get() {
        Ok(vec) => vec,
        Err(e) => {
            return Ok( 
                build_error_response( StatusCode::INTERNAL_SERVER_ERROR
                    , &format!("get_users() failed. {:?} - {}", e, e) 
                )
            );
        }
    };

    let mut items = Vec::new();
    for user in users {
        items.push(json!({
            "id": user.id,
            "username": user.username,
            "password": user.password,
            "level": user.level
        }));
    }

    let payload = json!({
        "success": true,
        "items": items
    });
    Ok(build_success_response(payload))
}



async fn save_user(req: Request<Body>, _client_addr : &SocketAddr) -> Result<Response<Body>, hyper::Error> {

    // Concatenate the body...
    let b = hyper::body::to_bytes(req).await?;
    let params = form_urlencoded::parse(b.as_ref())
        .into_owned()
        .collect::<HashMap<String, String>>();

    let mut user = data::User::default();
    if let Some(id) = params.get("id") {
        if let Ok(uid) = id.parse() {
            user.id = uid;
        }
    }

    if let Some(username) = params.get("username") {
        user.username = username.trim().to_string();
    }
    if let Some(password) = params.get("password") {
        user.password = password.trim().to_string();
    }
    if let Some(level) = params.get("level") {
        if let Ok(l) = level.parse() {
            user.level = l;
        }
    }

    if user.password.len() == 0 ||
        user.level > data::user::USER_LEVEL_ADMIN ||
        user.level < data::user::USER_LEVEL_INACTIVE ||
        (user.id > 0 && user.username.len() == 0) {
        return Ok( build_error_response( StatusCode::BAD_REQUEST, "Not all parameters are supplied!"));
    }

    if user.id > 0 {
        if let Err(e) = data::user::update(&user) {
            let error_msg = format!("data::user::update() failed. {}", e);
            error!("{}", &error_msg);
            return Ok( build_error_response( StatusCode::INTERNAL_SERVER_ERROR, &error_msg));
        }
    } else {
        if let Err(e) = data::user::add(&user) {
            let error_msg = format!("data::user::add() failed. {}", e);
            error!("{}", &error_msg);
            return Ok( build_error_response( StatusCode::INTERNAL_SERVER_ERROR, &error_msg));
        }
    }

    let payload = json!({
        "success": true
    });
    Ok(build_success_response(payload))
}



async fn del_user(req: Request<Body>, _client_addr : &SocketAddr) -> Result<Response<Body>, hyper::Error> {

    let params = form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>();

    let id : i32 = if let Ok(n) = params.get("id").unwrap_or(&"".to_string()).parse() {
        n
    } else {
        return Ok( build_error_response( StatusCode::BAD_REQUEST, "Missing parameter `id`") )
    };
    
    if let Err(e) = data::user::del(id){
        return Ok( build_error_response( StatusCode::INTERNAL_SERVER_ERROR, &format!("del_user failed. {:?}", e))  );
    }

    let payload = json!({
        "success": true
    });
    Ok(build_success_response(payload))
}