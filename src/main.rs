mod utils;

use actix_web::{get, post, web::{self}, Error, App, HttpResponse, HttpServer, Responder, HttpRequest, Result, dev::{ServiceRequest, ServiceResponse}, body::MessageBody, FromRequest, HttpMessage };
use actix_web_lab::middleware::{Next, from_fn};
use futures::future::{ok, err};
use std::{process::{Command, Stdio}, fs::File, collections::HashMap, sync::Mutex}; 
use log::info; 
use env_logger::Env;
use dotenv; 
use firestore::{ FirestoreDb, FirestoreDbOptions };
use serde::{Deserialize, Serialize};
use std::io::{Write};
use firebase_token::JwkAuth;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TunnelStruct {
    ipv4: String,
    port: u32,
    private_key: String,
    public_key: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PeerDocumentStruct {
    ipv4: String,
    private_key: String,
    public_key: String
}

struct PeerCache {
    user_id: String,
}

struct AppState {
    peers: Mutex<HashMap<String, PeerCache>>,
}

#[get("/")]
async fn root() -> impl Responder {
    HttpResponse::Ok().body("All Systems Operational!")
}

async fn add_peer(_req : HttpRequest, db : web::Data<FirestoreDb>, app_state: web::Data<AppState>, user : User) -> Result<impl Responder> {
    let wg_tunnel_id = dotenv::var("WG_TUNNEL_ID").expect("Environment Variable \"WG_TUNNEL_ID\" Retrieved"); 

    let mut peer_config: Result<Option<PeerDocumentStruct>, firestore::errors::FirestoreError> = db.fluent()
        .select()
        .by_id_in(format!("tunnels/{}/peers", wg_tunnel_id).as_str())
        .obj()
        .one(user.clone().user_id)
        .await;

    let mut peer_ipv4: String = "".to_string();

    if peer_config.as_ref().unwrap().is_none() { 
        info!("Peer Config Not Found for UserID: {}", user.user_id);

        // Generate Address; Handle Error if No Available Address
        for n in 2..255 {
            if !app_state.peers.lock().unwrap().contains_key(&format!("10.8.0.{}", n)) {
                peer_ipv4 = format!("10.8.0.{}", n);
                break; 
            }
        }

        assert_ne!(peer_ipv4, ""); // No IP Address was available!

        let wg_private_key = utils::generate_private_key(); 

        let peer = PeerDocumentStruct {
            public_key: utils::generate_public_key(&wg_private_key),
            private_key: wg_private_key,
            ipv4: peer_ipv4.clone()
        };

        peer_config = db.fluent()
            .update()
            .in_col(format!("tunnels/{}/peers", wg_tunnel_id).as_str())
            .document_id(user.clone().user_id)
            .object(&peer)
            .execute()
            .await;
    } else {
        peer_ipv4 = (&peer_config.as_ref().ok().as_ref().unwrap().as_ref().unwrap().ipv4).to_string();
    }

    utils::add_peer_to_conf(
        &peer_ipv4,
        &peer_config.as_ref().ok().as_ref().unwrap().as_ref().unwrap().public_key
    );
    // TODO: Validate if peer was actually added
    app_state.peers.lock().unwrap().insert(peer_ipv4.to_string(), PeerCache { user_id: user.clone().user_id });

    // Handle Error
    Ok(web::Json(peer_config.ok())) 
}

// TODO: Pure Reliance on DB Currently, Attempt Removal of Peer based on Client Data and Peer Cache 
#[post("/peer/remove")]
async fn remove_peer(app_state : web::Data<AppState>, db : web::Data<FirestoreDb>, user : User) -> impl Responder {
    let wg_tunnel_id = dotenv::var("WG_TUNNEL_ID").expect("Environment Variable \"WG_TUNNEL_ID\" Retrieved"); 

    let peer_config: Result<Option<PeerDocumentStruct>, firestore::errors::FirestoreError> = db.fluent()
        .select()
        .by_id_in(format!("tunnels/{}/peers", wg_tunnel_id).as_str())
        .obj()
        .one(&user.user_id)
        .await;

    if peer_config.as_ref().unwrap().as_ref().is_none() {
        HttpResponse::BadRequest().body("Peer Not Connected.");
    }

    let peer_ipv4 = &peer_config.as_ref().ok().as_ref().unwrap().as_ref().unwrap().ipv4;
    
    utils::remove_peer_from_conf(peer_ipv4, &peer_config.as_ref().ok().as_ref().unwrap().as_ref().unwrap().public_key);
    app_state.peers.lock().unwrap().remove(peer_ipv4);

    let _ = db.fluent()
        .delete()
        .from(format!("tunnels/{}/peers", wg_tunnel_id).as_str())
        .document_id(user.user_id)
        .execute()
        .await;

    HttpResponse::Ok().body("Removed Peer Successfully.")
}


#[derive(Clone)]
struct User {
    user_id : String
}

impl FromRequest for User {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        match req.extensions().get::<User>() {
            Some(user) => return ok(user.clone()),
            None => return err(actix_web::error::ErrorBadRequest("Error Called From User FromRequest"))
        };
    }
}

async fn auth_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    
    if req.path().starts_with("/peer") {
        let auth_header = std::str::from_utf8(req.headers().get("Authorization").unwrap().as_bytes()).unwrap().to_string(); 
        let auth_token = auth_header.split("Bearer").collect::<Vec<&str>>()[1].trim();
    
        let firebase_project_id = dotenv::var("FIREBASE_PROJECT_ID").expect("Retrieved FIREBASE_PROJECT_ID ENV Variable");   
    
        let jwk_auth = JwkAuth::new(firebase_project_id).await;
        let token_claim = jwk_auth.verify(auth_token).await;
    
        let user_id = token_claim.unwrap().claims.sub;

        req.extensions_mut().insert(User {
            user_id
        });
    }

    next.call(req).await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
   
    utils::generate_firebase_credentials_file();
   
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
        gcloud_sdk::TokenSourceType::File("src/firebase/credentials.json".into())
    ).await.expect("Failed to Connect to Firestore");

    let wg_private_key : String;
    let wg_public_key : String; 

    let tunnel_config: Result<Option<TunnelStruct>, firestore::errors::FirestoreError> = db.fluent()
        .select()
        .by_id_in("tunnels")
        .obj()
        .one(wg_tunnel_id.as_ref().unwrap().to_string())
        .await;

    if tunnel_config.as_ref().unwrap().is_none() {
        info!("Tunnel Doesn't Exist!");

        wg_private_key = utils::generate_private_key(); 
        wg_public_key = utils::generate_public_key(&wg_private_key);
    }
    else {
        wg_private_key = tunnel_config.as_ref().unwrap().as_ref().unwrap().clone().private_key;
        wg_public_key = tunnel_config.as_ref().unwrap().as_ref().unwrap().clone().public_key;
    }

    let tunnel_struct = TunnelStruct {
        ipv4: wg_host.unwrap().to_string(),
        port: wg_port.as_ref().unwrap().to_string().parse::<u32>().unwrap(),
        private_key: wg_private_key.clone(),
        public_key: wg_public_key
    };
    
    // Create or Update Tunnel Properties
    let updated_tunnel: Result<TunnelStruct, firestore::errors::FirestoreError> = db.fluent()
        .update()
        .in_col("tunnels")
        .document_id(wg_tunnel_id.unwrap().to_string())
        .object(&tunnel_struct)
        .execute()
        .await;

    let wg_conf = format!(r#"
# Note: Do not edit this file directly.
# Your changes will be overwritten!

# Server
[Interface]
PrivateKey = {}
Address = {}/24
ListenPort = {}
PreUp = 
PostUp = {}
PreDown = 
PostDown =
"#, 
updated_tunnel.as_ref().unwrap().private_key, 
"10.8.0.1",
updated_tunnel.as_ref().unwrap().port, 
"iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT;"
    );

    let wg_conf_path = dotenv::var("WG_CONF_PATH");    
    assert!(wg_conf_path.is_ok(), "Environment Variable \"WG_CONF_PATH\" Could not be found!");

    let path = format!("{}/wg0.conf", wg_conf_path.unwrap().to_string());
    let mut output = File::create(path)?;
    
    write!(output, "{}", wg_conf).expect("Updated wg0.conf");

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

    let app_state = web::Data::new(AppState {
        peers: Mutex::new(HashMap::new()), // TODO: Populate with clients from Firestore
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(web::Data::new(db.clone()))
            .service(root)
            .service(remove_peer)
            // .wrap_fn(|req, srv| {
            //     let auth_header = std::str::from_utf8(req.headers().get("Authorization").unwrap().as_bytes()).unwrap().to_string(); 
            //     let auth_token = auth_header.split("Bearer").collect::<Vec<&str>>()[1].trim_start();
     

            //     let fut = srv.call(req);
            //     async {
            //         let res = fut.await?;
            //         Ok(res)
            //     }
            // })
            .wrap(from_fn(auth_middleware))
            .route("/peer/add", web::post().to(add_peer))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}