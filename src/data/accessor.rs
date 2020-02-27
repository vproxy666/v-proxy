use std::sync::{ RwLock };
use std::io::{ self, Error, ErrorKind };

use rusqlite::{NO_PARAMS, Connection, OpenFlags, Error as SqlError};

use super::{ User, SslCertificate };

lazy_static! {
    static ref DB_PATH: RwLock<String> = RwLock::new("./data/db.sqlite".to_string());
}

pub fn initialize(sqlite_path : &str) -> Result<(), io::Error> {
    *DB_PATH.write().unwrap() = sqlite_path.to_string();
    let conn = match Connection::open_with_flags(sqlite_path, OpenFlags::SQLITE_OPEN_CREATE |
        OpenFlags::SQLITE_OPEN_READ_WRITE |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE){

        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to open SQLITE database at {}. {:?} - {}.", sqlite_path, e, e);
            return Err(Error::new( ErrorKind::Other, msg));
        }
    };

    if let Err(e) = conn. execute_batch(
        "CREATE TABLE IF NOT EXISTS 'main'.'config_item' 
        (
            'ID' INTEGER PRIMARY KEY AUTOINCREMENT,
            'Name' TEXT NOT NULL COLLATE NOCASE,
            'Value' TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS 'main'.'idx_config_Name' ON 'config_item' ('Name');

        CREATE TABLE IF NOT EXISTS 'main'.'ssl_certificate' 
        (
            'ID' INTEGER PRIMARY KEY AUTOINCREMENT,
            'Domain' TEXT NOT NULL COLLATE NOCASE,
            'Certificate' BLOB NOT NULL,
            'Key' BLOB NOT NULL,
            'Subject' TEXT NOT NULL COLLATE NOCASE,
            'Issuer' TEXT NOT NULL COLLATE NOCASE,
            'ValidFrom' TEXT NOT NULL COLLATE NOCASE,
            'ValidTo' TEXT NOT NULL COLLATE NOCASE
        );
        CREATE UNIQUE INDEX IF NOT EXISTS 'main'.'idx_ssl_certificate_Domain' ON 'ssl_certificate' ('Domain');

        CREATE TABLE IF NOT EXISTS 'main'.'user' 
        (
            'ID' INTEGER PRIMARY KEY AUTOINCREMENT,
            'Username' TEXT NOT NULL COLLATE NOCASE,
            'Password' TEXT NOT NULL COLLATE RTRIM,
            'Level' INTEGER  NOT NULL DEFAULT 0,
            'ValidTo' TEXT NOT NULL COLLATE NOCASE
        );
        CREATE UNIQUE INDEX IF NOT EXISTS 'main'.'idx_user_Username' ON 'user' ('Username');

        PRAGMA journal_mode=WAL;"
    ) 
    {
        panic!("Failed to initialize sqlite database. {:?} - {}.", e, e);
    }

    Ok(())
}


pub fn get_config_item(name : &str) -> Result<String, SqlError>  {
    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_READ_ONLY |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    match conn.query_row_named( "SELECT Value FROM 'main'.'config_item' WHERE Name=:name;",
        &[(":name", &name.to_string())],
        |row| row.get(0)
    ) {
        Ok(val) => return Ok(val),
        Err(e) => {
            if e == SqlError::QueryReturnedNoRows {
                return Ok("".to_string());
            }
            warn!("{:?} occurred on SELECT config_item : {}", e, e);
            return Err(e);
        }
    };
}



pub fn set_config_item(name : &str, val : &String) -> Result<(), SqlError>  {
    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_CREATE |
        OpenFlags::SQLITE_OPEN_READ_WRITE |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    match conn.execute_named( "REPLACE INTO 'main'.'config_item' (Name, Value) VALUES ( :name, :value );",
        &[(":name", &name.to_string()), (":value", val)],
    ) {
        Ok(_) => return Ok(()),
        Err(e) => {
            warn!("{:?} occurred on REPLACE INTO config_item : {}", e, e);
            return Err(e);
        }
    };
}




pub fn get_ssl_certificates() -> Result<Vec<SslCertificate>, SqlError>  {
    let mut vec = Vec::new();
    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_READ_ONLY |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    let mut stmt = conn.prepare("SELECT ID, Domain, Certificate, Key, Subject, Issuer, ValidFrom, ValidTo  FROM 'main'.'ssl_certificate';")?;
    let iter = stmt.query_map( NO_PARAMS, |row| {
        Ok(SslCertificate {
            id: row.get(0)?,
            domain: row.get(1)?,
            certificate: row.get(2)?,
            key: row.get(3)?,
            subject: row.get(4)?,
            issuer: row.get(5)?,
            valid_from: row.get(6)?,
            valid_to: row.get(7)?,
        })
    })?;
    for item in iter {
        vec.push(item.unwrap());
    }
    return Ok(vec);
}



pub fn add_ssl_certificates(ssl_certificate : &SslCertificate) -> Result<(), SqlError>  {

    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_CREATE |
        OpenFlags::SQLITE_OPEN_READ_WRITE |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    conn.execute_named("
    INSERT INTO ssl_certificate(Domain, Certificate, Key, Subject, Issuer, ValidFrom, ValidTo) 
    VALUES (:domain, :certificate, :key, :subject, :issuer, :valid_from, :valid_to);",
        &[
            (":domain", &ssl_certificate.domain),
            (":certificate", &ssl_certificate.certificate),
            (":key", &ssl_certificate.key),
            (":subject", &ssl_certificate.subject.as_ref().map(|s| s.as_str()).unwrap_or("")),
            (":issuer", &ssl_certificate.issuer.as_ref().map(|s| s.as_str()).unwrap_or("")),
            (":valid_from", &ssl_certificate.valid_from.as_ref().map(|s| s.as_str()).unwrap_or("")),
            (":valid_to", &ssl_certificate.valid_to.as_ref().map(|s| s.as_str()).unwrap_or("")),
        ]
    )?;
    Ok(())
}


pub fn save_ssl_certificates(ssl_certificate : &SslCertificate) -> Result<(), SqlError>  {

    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_CREATE |
        OpenFlags::SQLITE_OPEN_READ_WRITE |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    conn.execute_named("
    REPLACE INTO ssl_certificate(Domain, Certificate, Key, Subject, Issuer, ValidFrom, ValidTo) 
    VALUES (:domain, :certificate, :key, :subject, :issuer, :valid_from, :valid_to);",
        &[
            (":domain", &ssl_certificate.domain),
            (":certificate", &ssl_certificate.certificate),
            (":key", &ssl_certificate.key),
            (":subject", &ssl_certificate.subject.as_ref().map(|s| s.as_str()).unwrap_or("")),
            (":issuer", &ssl_certificate.issuer.as_ref().map(|s| s.as_str()).unwrap_or("")),
            (":valid_from", &ssl_certificate.valid_from.as_ref().map(|s| s.as_str()).unwrap_or("")),
            (":valid_to", &ssl_certificate.valid_to.as_ref().map(|s| s.as_str()).unwrap_or("")),
        ]
    )?;
    Ok(())
}


pub fn del_ssl_certificate(id : i32) -> Result<(), SqlError>  {

    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_CREATE |
        OpenFlags::SQLITE_OPEN_READ_WRITE |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    conn.execute_named("DELETE FROM ssl_certificate WHERE ID = :id;",
        &[ (":id", &id) ]
    )?;
    Ok(())
}



// Add a new user, return its ID;  if zero is returned, the user already exists
pub fn insert_user(user : &User) -> Result<(), SqlError>  {
    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_CREATE |
        OpenFlags::SQLITE_OPEN_READ_WRITE |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    conn.execute_named("INSERT INTO 'main'.'user' (Username, Password, Level, ValidTo) VALUES ( :username, :password, :level, '2099-01-01T00:00:00' );"
        , &[ (":username", &user.username), (":password", &user.password), (":level", &user.level) ]
        )?;
    Ok(())
}


pub fn update_user(user : &User) -> Result<(), SqlError>  {
    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_CREATE |
        OpenFlags::SQLITE_OPEN_READ_WRITE |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    match conn.execute_named( "UPDATE 'main'.'user' SET Password=:password, Level=:level WHERE ID=:id;",
        &[
            (":id", &user.username),
            (":password", &user.password),
            (":level", &user.level),
        ],
    ) {
        Ok(num) => {
            if num > 0 {
                return Ok(());
            }
            return Err(SqlError::InvalidParameterName("No row is updated".to_string()));
        },
        Err(e) => {
            return Err(e);
        }
    };
}


pub fn delete_user(id : i32) -> Result<String, SqlError>  {
    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_CREATE |
        OpenFlags::SQLITE_OPEN_READ_WRITE |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    let username = conn.query_row_named("SELECT Username from 'main'.'user' WHERE ID=:id; ",
        &[ (":id", &id) ],
        |row| row.get(0)
    )?;

    conn.execute_named( "DELETE FROM 'main'.'user' WHERE ID=:id;", &[ (":id", &id) ])?;

    Ok(username)
}



pub fn get_users() -> Result<Vec<User>, SqlError>  {
    let mut vec = Vec::new();
    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_READ_ONLY |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    let mut stmt = conn.prepare("SELECT ID, Username, Password, Level  FROM 'main'.'user';")?;
    let iter = stmt.query_map( NO_PARAMS, |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            password: row.get(2)?,
            level: row.get(3)?,
        })
    })?;
    for item in iter {
        vec.push(item.unwrap());
    }
    return Ok(vec);
}



pub fn get_user(username : String) -> Result<Option<User>, SqlError>  {

    let db_path = &DB_PATH.read().unwrap();

    let conn = Connection::open_with_flags(db_path.as_str(), OpenFlags::SQLITE_OPEN_READ_ONLY |
        OpenFlags::SQLITE_OPEN_NO_MUTEX |
        OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;

    let mut stmt = conn.prepare("SELECT ID, Username, Password, Level  FROM 'main'.'user' WHERE Username = :username;")?;
    let iter = stmt.query_map_named( &[ (":username", &username) ], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            password: row.get(2)?,
            level: row.get(3)?,
        })
    })?;
    for item in iter {
        return Ok(Some(item.unwrap()));
    }
    return Ok(None);
}