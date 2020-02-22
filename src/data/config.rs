use std::sync::{ RwLock };
use std::collections::HashMap;
use super::accessor;

use uuid::Uuid;

static CONSOLE_PATH: &'static str = "CONSOLE_PATH";
static ORIGIN_URL: &'static str = "ORIGIN_URL";
static DISGUISE_MODE: &'static str = "DISGUISE_MODE";
static HTTP_PROXY: &'static str = "HTTP_PROXY";
static ENABLED: &'static str = "ENABLED";
static DISABLED: &'static str = "DISABLED";

// to avoid frequent lookup database, we use a hashmap to cache
lazy_static! {
    static ref HASH_MAP: RwLock<HashMap<&'static str, String>> = RwLock::new(HashMap::new());
}

fn get_cached_config_item(name : &'static str) -> Option<String> {
    let hash_map = HASH_MAP.read().unwrap();
    hash_map.get(name).and_then( |val| Some(val.clone()) )
}

fn set_cached_config_item(name : &'static str, val : String) {
    let mut hash_map = HASH_MAP.write().unwrap();
    hash_map.insert(name, val);
}

fn get_config_item(name : &'static str) -> Option<String> {
    get_cached_config_item(name).or_else(|| {
        match accessor::get_config_item(name) {
            Err(e) => panic!("Failed to read {} from db. {}", name, e),
            Ok(val) => {
                let val = val.trim();
                set_cached_config_item(name, val.to_string());
                return Some(val.to_string());
            }
        }
    })
}


fn set_config_item(name : &'static str, val : String)  {
    if let Err(e) = accessor::set_config_item( name, &val) {
        panic!("Failed to write {} into db. {}", name, e);
    }
    set_cached_config_item(name, val);
}

// Get backend path
pub fn get_console_path() -> String {
    match get_config_item(CONSOLE_PATH) {
        Some(val) if !val.is_empty() => val,
        _ => {
            let val = format!("/{}/", Uuid::new_v4().to_simple().to_string());
            set_config_item(CONSOLE_PATH, val.clone());
            val
        } 
    }
}

#[allow(dead_code)]
// Set backend path
pub fn set_console_path(path : &str) {
    set_config_item(CONSOLE_PATH, path.to_string());
}



// Get origin path
pub fn get_origin_url() -> String {
    match get_config_item(ORIGIN_URL) {
        Some(val) if !val.is_empty() => val,
        _ => {
            "http://beian.miit.gov.cn".to_string()
        } 
    }
}


// Set backend path
pub fn set_origin_url(path : &str) {
    set_config_item(ORIGIN_URL, path.to_string());
}




pub fn enable_disguise_mode(enabled : bool) {
    if enabled {
        set_config_item(DISGUISE_MODE, ENABLED.to_string());
    } else {
        set_config_item(DISGUISE_MODE, DISABLED.to_string());
    }
}

pub fn enable_http_proxy(enabled : bool) {
    if enabled {
        set_config_item(HTTP_PROXY, ENABLED.to_string());
    } else {
        set_config_item(HTTP_PROXY, DISABLED.to_string());
    }
}

pub fn is_disguise_mode_enabled() -> bool {
    match get_config_item(DISGUISE_MODE) {
        Some(val) => val != DISABLED,
        _ => {
            true
        } 
    }
}

pub fn is_http_proxy_enabled() -> bool {
    match get_config_item(HTTP_PROXY) {
        Some(val) => val == ENABLED,
        _ => {
            false
        } 
    }
}