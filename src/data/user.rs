


use std::sync::{ RwLock, Arc };
use std::collections::HashMap;
use rusqlite::{Error as SqlError};
use super::accessor;


// to avoid frequent lookup database, we use a hashmap to cache
lazy_static! {
    static ref HASH_MAP: RwLock<HashMap<String, Arc<User>>> = RwLock::new(HashMap::new());
}

pub static USER_LEVEL_INACTIVE : i32 = 0;
pub static USER_LEVEL_NORMAL : i32 = 1;
pub static USER_LEVEL_ADMIN : i32 = 2;


pub struct User {
    pub id: u32,
    pub username: String,
    pub password: String,
    pub level: i32,
}

impl User {
    pub fn default() -> User {
        User {
            id : 0,
            username : "".to_string(),
            password : "".to_string(),
            level : USER_LEVEL_INACTIVE,
        }
    }
    pub fn get_by_username(username : String) -> Option<Arc<User>> {
        {
            let hash_map = HASH_MAP.read().unwrap();
            if let Some(user) = hash_map.get(&username) {
                return Some(user.clone());
            }
        }

        match accessor::get_user(username){
            Ok(opt) =>  {
                if opt.is_none() {
                    return None;
                }
                let mut hash_map = HASH_MAP.write().unwrap();
                let user = Arc::new(opt.unwrap());
                hash_map.insert( user.username.clone(), user.clone());
                return Some(user);
            },
            Err(e) => {
                error!("get_by_username() failed. {}", e);
            }
        } 
        None
    }
}

pub fn get() -> Result<Vec<User>, SqlError> {
    accessor::get_users()
}


pub fn add(user : &User) -> Result<(), SqlError> {
    accessor::insert_user(user)
}

pub fn update(user : &User) -> Result<(), SqlError> {
    accessor::update_user(user).and_then(|_| {
        match accessor::get_user(user.username.clone()){
            Ok(opt) =>  {
                if !opt.is_none() {
                    let mut hash_map = HASH_MAP.write().unwrap();
                    if hash_map.contains_key(&user.username) {
                        let user = Arc::new(opt.unwrap());
                        hash_map.insert( user.username.clone(), user.clone());
                    }
                }
            },
            Err(e) => {
                error!("get_by_username() failed. {}", e);
            }
        };
        Ok(())
    })
}


pub fn del(id : i32) -> Result<(), SqlError> {
    accessor::delete_user(id).and_then(|username|{
        let mut hash_map = HASH_MAP.write().unwrap();
        hash_map.remove(&username);
        Ok(())
    })
}

