


use std::net::{ SocketAddr };
use async_std::sync::{ RwLock };
use hyper::{Body, Request, Response};
use http::header;

use hyper_staticfile;

use crate::auth;
use crate::data::config;
use crate::api_server;

use crate::data::user::{self };

lazy_static! {
    static ref STATIC_WEBSITE: RwLock<Option<hyper_staticfile::Static>> = RwLock::new(Some(hyper_staticfile::Static::new("web")));
}

pub async fn set_root(path : &str) {
    let mut static_website = STATIC_WEBSITE.write().await;
    *static_website = Some(hyper_staticfile::Static::new(path));
}


/* Rewrite URL if it is a backend request */
pub fn url_rewrite( req: &mut Request<Body>) -> bool {

    if req.uri().authority().is_none()  { // if authority is None, it is not an HTTP proxy request
        if let Some(path_and_query) = req.uri().path_and_query() {
            let path_and_query = path_and_query.as_str();
            let backend_path = config::get_console_path();
            if path_and_query.starts_with(backend_path.as_str()) {
                // modify URI
                let mut path_and_query = path_and_query[backend_path.len()..].to_string();
                if !path_and_query.starts_with("/") {
                    path_and_query.insert(0, '/');
                }

                *(req.uri_mut()) = path_and_query.parse().unwrap();
                return true;
            }
        }
    }
    return false;
}

pub async fn handle(req: Request<Body>, client_addr : SocketAddr) -> Result<Response<Body>, hyper::Error> {

    // validate the credentials
    let header = req.headers().get(header::AUTHORIZATION);
    let _session_user = match auth::basic_authenticate(header) {
        Some(u) if u.level >= user::USER_LEVEL_ADMIN => u,
        _ => {
            let mut resp = Response::new(Body::empty());
            let headers = resp.headers_mut();
            headers.insert(header::WWW_AUTHENTICATE, "Basic".parse().unwrap());
            headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
            *resp.status_mut() = http::StatusCode::UNAUTHORIZED;
            return Ok(resp);
        }
    };


    if req.uri().path().starts_with("/api/") {
        return api_server::handle(req, client_addr).await;
    }

    // serve as static web sites
    let guard = STATIC_WEBSITE.read().await;
    if let Some(static_website) = guard.as_ref() {
        match static_website.clone().serve(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                let msg = format!("Unable to serve this request. \n\n{:?} - {}", e, e);
                let mut resp = Response::new(Body::from(msg));
                let headers = resp.headers_mut();
                headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
                *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(resp);
            }
        }
    } else {
        let mut resp = Response::new(Body::from("Management web site cannot be found, please check configuration."));
        let headers = resp.headers_mut();
        headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
        *resp.status_mut() = http::StatusCode::NOT_FOUND;
        return Ok(resp);
    }
    
}