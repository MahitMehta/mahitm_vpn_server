use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder };
use std::process::Command; 
use log::info; 
use env_logger::Env;

#[get("/")]
async fn hello() -> impl Responder {
    info!("Pinged Root: /");
    HttpResponse::Ok().body("Hello world!")
}

#[get("/create-file")]
async fn api() -> impl Responder {
    Command::new("touch")
        .arg("file.txt")
        .output()
        .expect("failed to execute process");

    HttpResponse::Ok().body("Created File")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(echo)
            .service(api)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}