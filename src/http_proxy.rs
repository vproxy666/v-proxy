


use std::net::{ SocketAddr };
use futures_util::future::try_join;
use hyper::upgrade::Upgraded;
use hyper::{Body, Client, Method, Request, Response};
use http::header;

use tokio;
use tokio::net::{ TcpStream };


use crate::auth;
use crate::upstream;
use crate::data::{ user, config };

type HttpClient = Client<hyper::client::HttpConnector>;






pub async fn handle(req: Request<Body>, _client_addr : SocketAddr) -> Result<Response<Body>, hyper::Error> {
 
    
    if let Some(auth) = req.uri().authority() { // if authority is not None, it is a HTTP proxy request
        // check HTTP header PROXY_AUTHORIZATION
        let header = req.headers().get(header::PROXY_AUTHORIZATION);
        let session_user = auth::basic_authenticate(header);

        if !config::is_disguise_mode_enabled() || session_user.is_some() {
        
            let _session_user = match session_user {
                Some(u) if u.level >= user::USER_LEVEL_NORMAL => u,
                _ => {
                    let mut resp = Response::new(Body::empty());
                    let headers = resp.headers_mut();
                    headers.insert(header::PROXY_AUTHENTICATE, "Basic".parse().unwrap());
                    headers.insert(header::CONNECTION, "close".parse().unwrap());
                    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
                    *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
                    return Ok(resp);
                }
            };


            if Method::CONNECT == req.method() {
                // Received an HTTP request like:
                // ```
                // CONNECT www.domain.com:443 HTTP/1.1
                // Host: www.domain.com:443
                // Proxy-Connection: Keep-Alive
                // ```
                //
                // When HTTP method is CONNECT we should return an empty body
                // then we can eventually upgrade the connection and talk a new protocol.
                //
                // Note: only after client received an empty body with STATUS_OK can the connection be upgraded, 
                // so we can't return a response inside `on_upgrade` future.
                let addr = auth.to_string();
                tokio::task::spawn(async move {
                    match req.into_body().on_upgrade().await {
                        Ok(upgraded) => {
                            if let Err(e) = tunnel(upgraded, addr).await {
                                error!("server io error: {}", e);
                            };
                        }
                        Err(e) => error!("upgrade error: {}", e),
                    }
                });
                return  Ok(Response::new(Body::empty()));
            } else {
                return HttpClient::new().request(req).await;
            }
        }
    }

    // behaves as a reserve proxy to pretend as a web site
    upstream::request(req).await
}


// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;

    // Proxying data
    let amounts = {
        let (mut server_rd, mut server_wr) = server.split();
        let (mut client_rd, mut client_wr) = tokio::io::split(upgraded);

        let client_to_server = tokio::io::copy(&mut client_rd, &mut server_wr);
        let server_to_client = tokio::io::copy(&mut server_rd, &mut client_wr);

        try_join(client_to_server, server_to_client).await
    };

    // Print message when done
    match amounts {
        Ok((_from_client, _from_server)) => {
            /*
            println!(
                "client wrote {} bytes and received {} bytes",
                from_client, from_server
            );
            */
        }
        Err(e) => {
            warn!("HTTP/1.1 tunnel error: {}", e);
        }
    };
    Ok(())
}


