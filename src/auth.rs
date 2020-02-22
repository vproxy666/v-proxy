
use std::sync::Arc;
use http::header::HeaderValue;
use regex::Regex;
use base64;

use crate::data::user::{User};

lazy_static! {
    static ref RE: Regex = Regex::new(r"^(?:Basic\s+)(?P<base64>.+)").unwrap();
}


pub fn basic_authenticate(proxy_auth : Option<&HeaderValue>) -> Option<Arc<User>> {

    if let Some(auth) = proxy_auth {
        if let Ok(header_value) = auth.to_str() {

            if let Some(caps) = RE.captures(header_value) {
                if let Some(b64) = caps.name("base64") {
                    if let Ok(decoded_buf) = base64::decode(b64.as_str()) {
                        let decoded_str = String::from_utf8_lossy(&decoded_buf);
                        if let Some(idx) = decoded_str.find(':') {

                            let username = &decoded_str[0..idx];
                            let password = &decoded_str[idx+1..];

                            if let Some(user) = User::get_by_username(username.to_string()){
                                if user.password == password {
                                    return Some(user);
                                } else {
                                    info!("Invalid credential. User `{}` password is not `{}`", username, password);
                                }
                            } else {
                                info!("Invalid credential. User `{}` does not exist", username);
                            }
                            
                            
                        }// if let Some(idx) = decoded_str.find(':')
                    }// if let Some(decoded) = base64::decode(b64)
                }// if let Some(base64) = caps.name("base64")
            }// if let Some(caps) = RE.captures(auth) {
        }
    } else {
        debug!("AUTHORIZATION http header is missing.");
    }

    None
}