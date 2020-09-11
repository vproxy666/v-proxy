#![recursion_limit="256"]
#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;
extern crate env_logger;
extern crate clap;


use std::env;
use std::sync::Arc;
use std::path::Path;
use std::fs;
use tokio;

use uuid::Uuid;


mod auth;
mod http_proxy;
mod upstream;
mod tcp_server;
mod web_server;
mod api_server;
mod data;
mod misc;
mod letsencrypt;

use data::user::{ self, User};

pub static VERSION: &str = "0.2.8";

// Get dir
pub fn get_dir(folder : &str) -> String {
    match env::current_exe() {
        Ok(exe_path) => {
            if let Some(parent_path) = exe_path.as_path().parent() {
                if let Some(dir) = parent_path.join(folder).to_str() {
                    return dir.to_string();
                }
            }
        },
        Err(e) => {
            error!("std::env::current_exe() failed. {:?}", e);
        }
    }
    return format!("./{}", folder);
}

#[tokio::main(threaded_scheduler)]
async fn main() {

    env_logger::init();

    let default_data_dir = get_dir("data");
    let default_web_root = get_dir("web");
    let default_pwd = Uuid::new_v4().to_simple().to_string();
    let matches = clap::App::new("VProxy")
        .version(VERSION)
        .author("github.com/vproxy666/v-proxy")
        .about("HTTPS proxy + Reverse proxy with integrated management console")
        .arg(clap::Arg::with_name("data_dir")
            .long("data_dir")
            .help("Sets path of directory to store data")
            .default_value(&default_data_dir)
            .required(false)
            .takes_value(true))
        .arg(clap::Arg::with_name("web_root")
            .long("web_root")
            .help("Sets path of directory where management web site locates")
            .default_value(&default_web_root)
            .required(false)
            .takes_value(true))
        .arg(clap::Arg::with_name("https_port")
            .long("https_port")
            .help("Sets listening port of HTTPS")
            .default_value("443")
            .required(false)
            .takes_value(true))
        .arg(clap::Arg::with_name("http_port")
            .long("http_port")
            .help("Sets listening port of HTTP. Set 0 to disable HTTP")
            .default_value("80")
            .required(false)
            .takes_value(true))
        .arg(clap::Arg::with_name("root_default_pwd")
            .long("root_default_pwd")
            .help("Default password of root user. Note this parameter is ignored if password was set.")
            .default_value(&default_pwd[0..12])
            .required(false)
            .takes_value(true))
        .get_matches();

    let http_port : u16 = matches.value_of("http_port").unwrap_or("80").parse().expect("`http_port` parameter is invalid");
    let https_port : u16 = matches.value_of("https_port").unwrap_or("443").parse().expect("`https_port` parameter is invalid");
    let data_dir = matches.value_of("data_dir").unwrap_or(&default_data_dir);
    let web_root = matches.value_of("web_root").unwrap_or(&default_web_root);
    let default_pwd = matches.value_of("default_pwd").unwrap_or(&default_pwd[0..12]);


    println!("
    $$\\    $$\\       $$$$$$$\\                                          
    $$ |   $$ |      $$  __$$\\                                         
    $$ |   $$ |      $$ |  $$ | $$$$$$\\   $$$$$$\\  $$\\   $$\\ $$\\   $$\\ 
    \\$$\\  $$  |      $$$$$$$  |$$  __$$\\ $$  __$$\\ \\$$\\ $$  |$$ |  $$ |
     \\$$\\$$  /       $$  ____/ $$ |  \\__|$$ /  $$ | \\$$$$  / $$ |  $$ |
      \\$$$  /        $$ |      $$ |      $$ |  $$ | $$  $$<  $$ |  $$ |
       \\$  /         $$ |      $$ |      \\$$$$$$  |$$  /\\$$\\ \\$$$$$$$ |
        \\_/          \\__|      \\__|       \\______/ \\__/  \\__| \\____$$ |
                                                             $$\\   $$ |
                                                             \\$$$$$$  |
                                                              \\______/ 
");

    println!("---------------------- V PROXY --------------------------");
    println!("Version                  : {}", VERSION);
    println!("HTTP Port                : {}", http_port);
    println!("HTTPS Port               : {}", https_port);
    println!("Web Root Path            : {}", web_root);
    println!("Data Directory           : {}", data_dir);
    {
        let p = Path::new(data_dir);
        if let Err(e) = data::initialize(&p) {
            error!("{}", e);
            warn!("尝试运行此命令给予权限: sudo chmod a+rw -R \"DATA文件夹路径\"");
            info!("Fatal error, exiting ....");
            return;
        }
    }

    println!("Console Path             : {}", data::config::get_console_path());
    let challenge_root = Path::new(data_dir).join("challenge");
    if let Err(e) = fs::create_dir_all(&challenge_root) {
        error!("Unable to create directory {} : {}", &challenge_root.to_str().unwrap_or(""), e);
        warn!("尝试运行此命令给予权限: sudo chmod a+rw -R \"DATA文件夹路径\"");
        info!("Fatal error, exiting ....");
        return;
    }
    data::config::set_challenge_root(challenge_root.to_str().unwrap());
    web_server::set_root(web_root, challenge_root.to_str().unwrap()).await;

    println!("Reverse Proxy Origin URL : {}", data::config::get_origin_url());
    match data::config::get_origin_url().parse() {
        Ok(uri) => upstream::set_uri(uri),
        Err(e) => warn!("Invalid Origin URL. {}", e),
    }

    let root_user = match User::get_by_username("root".to_string()){
        Some(u) => u,
        None => {
            let mut new_user = user::User::default();
            new_user.username = "root".to_string();
            new_user.password = default_pwd.to_string();
            new_user.level = user::USER_LEVEL_ADMIN;
            match data::user::add(&new_user) {
                Ok(_) => {
                    Arc::new(new_user)
                },
                Err(e) => {
                    panic!("Unable to create root user. {}", e);
                }
            }
        }
    };
    

    

    println!("---------------------------------------------------------\n");
    println!("Username    : {}", &root_user.username);
    println!("Password    : {}", &root_user.password);
    println!("Console URL :");

    if let Ok(ssl_certificates) = data::get_ssl_certificates() {
        for ssl_cert in ssl_certificates {
            println!("https://{}:{}{}"
                , ssl_cert.domain
                , https_port
                , data::config::get_console_path()
                );
        }
    }

    println!("http://{}:{}{}"
        , misc::get_local_ip()
        , http_port
        , data::config::get_console_path()
        );


    println!("\n---------------------------------------------------------");

    
    tcp_server::run(http_port, https_port).await.unwrap();
}

