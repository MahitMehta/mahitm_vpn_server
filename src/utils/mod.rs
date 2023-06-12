use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use log::info;
use serde::{Serialize};
use serde_json;

#[derive(Serialize)]
struct FirebaseCredentials {
    client_id: String,
    client_secret: String,
    quota_project_id: String,
    refresh_token: String,

    #[serde(rename = "type")]
    account_type: String
}

pub(crate) fn generate_firebase_credentials_file() {
    let firebase_project_id = dotenv::var("FIREBASE_PROJECT_ID");    
    assert!(firebase_project_id.is_ok(), "Environment Variable \"FIREBASE_PROJECT_ID\" Could not be found!");

    let firebase_client_id = dotenv::var("FIREBASE_CLIENT_ID");    
    assert!(firebase_client_id.is_ok(), "Environment Variable \"FIREBASE_CLIENT_ID\" Could not be found!");
    
    let firebase_client_secret = dotenv::var("FIREBASE_CLIENT_SECRET");    
    assert!(firebase_client_secret.is_ok(), "Environment Variable \"FIREBASE_CLIENT_SECRET\" Could not be found!");

    let firebase_refresh_token = dotenv::var("FIREBASE_REFRESH_TOKEN");    
    assert!(firebase_refresh_token.is_ok(), "Environment Variable \"FIREBASE_REFRESH_TOKEN\" Could not be found!");

    let firebase_credentials = FirebaseCredentials {
        client_id: firebase_client_id.ok().unwrap(),
        client_secret: firebase_client_secret.ok().unwrap(),
        quota_project_id: firebase_project_id.ok().unwrap(),
        refresh_token: firebase_refresh_token.ok().unwrap(),
        account_type: "authorized_user".to_string()
    };

    let json = serde_json::to_string(&firebase_credentials)
        .expect("Constructed JSON Representation of struct FirebaseCredentials");

    let mut output = File::create("src/firebase/credentials.json").expect("Initiated creation of Firebase Credentials file");
    write!(output, "{}", json).expect("Injected Credentials into Firebase Credentials File");
}

pub(crate) fn generate_private_key() -> String {
    let private_key = Command::new("wg")
    .arg("genkey")
    .stdout(Stdio::piped())
    .output()
    .expect("Failed to Generate New Private Key");

    return String::from(String::from_utf8(private_key.stdout).unwrap().trim());
}

pub(crate) fn generate_public_key(wg_private_key : &String) -> String {
    let mut public_key = Command::new("wg")
    .arg("pubkey")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()
    .expect("Failed to Generate New Public Key");

    let stdin = public_key.stdin.as_mut().expect("Failed to open stdin");
    stdin.write_all(wg_private_key.as_bytes()).expect("Failed to write to stdin");

    let public_key_output = public_key.wait_with_output().expect("Failed to read stdout");
    return String::from(String::from_utf8(public_key_output.stdout).unwrap().trim());
}

pub(crate) fn add_peer_to_conf(peer_ipv4 : &String, peer_public_key: &String) {
    let output = Command::new("wg")
    .args([
        "set", "wg0", "peer", 
         peer_public_key,
        "allowed-ips",
        format!("{}/32",peer_ipv4).as_str()
    ])
    .stdout(Stdio::piped())
    .output()
    .expect("Added peer to wg0");

    let stderr = String::from_utf8(output.stderr).unwrap();
    info!("STDERR:");
    info!("{}", stderr);

    let output = Command::new("ip")
    .args([
        "-4", "route", "add", format!("{}/32",peer_ipv4).as_str(), "dev", "wg0"
    ])
    .stdout(Stdio::piped())
    .output()
    .expect("Added peer route");

    let stderr = String::from_utf8(output.stderr).unwrap();
    info!("STDERR:");
    info!("{}", stderr);
}

pub(crate) fn remove_peer_from_conf(peer_ipv4 : &String, peer_public_key: &String) {
    let output = Command::new("wg")
    .args([
        "set", "wg0", "peer", 
         peer_public_key,
        "remove"
    ])
    .stdout(Stdio::piped())
    .output()
    .expect("Removed peer from wg0");

    let stderr = String::from_utf8(output.stderr).unwrap();
    info!("STDERR:");
    info!("{}", stderr);

    let output = Command::new("ip")
    .args([
        "-4", "route", "delete", format!("{}/32",peer_ipv4).as_str(), "dev", "wg0"
    ])
    .stdout(Stdio::piped())
    .output()
    .expect("Deleted peer route");

    let stderr = String::from_utf8(output.stderr).unwrap();
    info!("STDERR:");
    info!("{}", stderr);
}