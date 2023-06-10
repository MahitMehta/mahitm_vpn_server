use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder };
use std::{process::{Command, Stdio}}; 
use log::info; 
use env_logger::Env;
use dotenv; 
use firestore::{ FirestoreDb, FirestoreDbOptions };
use serde::{Deserialize, Serialize};
use std::io::{Write};

#[get("/")]
async fn hello() -> impl Responder {
    info!("Pinged Root: /");
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TunnelStruct {
    ipv4: String,
    port: u32,
    private_key: String,
    public_key: String
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
   
    let firebase_project_id = dotenv::var("FIREBASE_PROJECT_ID");    
    assert!(firebase_project_id.is_ok(), "Environment Variable \"FIREBASE_PROJECT_ID\" Could not be found!");

    let wg_host = dotenv::var("WG_HOST");    
    assert!(wg_host.is_ok(), "Environment Variable \"WG_HOST\" Could not be found!");

    let wg_port = dotenv::var("WG_PORT");    
    assert!(wg_port.is_ok(), "Environment Variable \"WG_PORT\" Could not be found!");

    let wg_tunnel_id = dotenv::var("WG_TUNNEL_ID");    
    assert!(wg_tunnel_id.is_ok(), "Environment Variable \"WG_TUNNEL_ID\" Could not be found!");

    let db = FirestoreDb::with_options_token_source(
        FirestoreDbOptions::new(firebase_project_id.as_ref().unwrap().to_string()),
        gcloud_sdk::GCP_DEFAULT_SCOPES.clone(),
        gcloud_sdk::TokenSourceType::File("src/config/firebase_credentials.json".into())
    ).await;

    let wg_private_key : String;
    let wg_public_key : String; 

    let tunnel_config: Result<Option<TunnelStruct>, firestore::errors::FirestoreError> = db.as_ref().unwrap().fluent()
        .select()
        .by_id_in("tunnels")
        .obj()
        .one(wg_tunnel_id.as_ref().unwrap().to_string())
        .await;

    if tunnel_config.as_ref().unwrap().is_none() {
        info!("Tunnel Doesn't Exist!");

        let private_key = Command::new("wg")
            .arg("genkey")
            .stdout(Stdio::piped())
            .output()
            .expect("Failed to Generate New Private Key");

        wg_private_key = String::from_utf8(private_key.stdout).unwrap();

        let mut public_key = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to Generate New Public Key");

        let stdin = public_key.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(wg_private_key.as_bytes()).expect("Failed to write to stdin");

        let public_key_output = public_key.wait_with_output().expect("Failed to read stdout");
        wg_public_key = String::from_utf8(public_key_output.stdout).unwrap();
    }
    else {
        wg_private_key = tunnel_config.as_ref().unwrap().as_ref().unwrap().clone().private_key;
        wg_public_key = tunnel_config.as_ref().unwrap().as_ref().unwrap().clone().public_key;
    }

    let tunnel_struct = TunnelStruct {
        ipv4: wg_host.unwrap().to_string(),
        port: wg_port.unwrap().to_string().parse::<u32>().unwrap(),
        private_key: wg_private_key,
        public_key: wg_public_key
    };
    
    // Create or Update Tunnel Properties
    let _object_returned: Result<TunnelStruct, firestore::errors::FirestoreError> = db.unwrap().fluent()
        .insert()
        .into("tunnels")
        .document_id(wg_tunnel_id.unwrap().to_string())
        .object(&tunnel_struct)
        .execute()
        .await;

    Command::new("wg-quick")
        .args(["down", "wg0"])
        .output()
        .expect("failed to execute process");

    let output = Command::new("wg-quick")
        .args(["up", "wg0"])
        .stdout(Stdio::piped())
        .output()
        .expect("failed to execute process");

    let stderr = String::from_utf8(output.stderr).unwrap();
    info!("STDERR:");
    info!("{}", stderr);

    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(echo)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}