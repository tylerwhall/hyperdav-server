extern crate env_logger;
extern crate hyper;
extern crate hyperdav_server;

use std::path::Path;

fn main() {
    env_logger::init().unwrap();

    let server = hyper::server::Server::http("0.0.0.0:8080").unwrap();
    server
        .handle(hyperdav_server::Server::new("", Path::new("/")))
        .unwrap();
}
