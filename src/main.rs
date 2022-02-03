extern crate bytes;
extern crate tokio;

use tokio::net::TcpListener;

mod errors;
mod messages;
mod client;

#[tokio::main]
async fn main() {
    println!("> Welcome to PgRabbit");

    let listener = match TcpListener::bind("0.0.0.0:5433").await {
        Ok(sock) => sock,
        Err(err) => {
            println!("> Error: {:?}", err);
            return;
        }
    };

    loop {
        let (socket, addr) = match listener.accept().await {
            Ok((socket, addr)) => (socket, addr),
            Err(err) => {
                println!("> Listener: {:?}", err);
                continue;
            }
        };

        // Client goes to another thread, bye.
        tokio::task::spawn(async move {
            println!(">> Client {:?} connected", addr);

            match client::Client::startup(socket).await {
                Ok(mut client) => {
                    println!(">> Client {:?} connected successfully!", addr);
                    client.handle().await;
                },

                Err(err) => {
                    println!(">> Error: {:?}", err);
                }
            };
        });
    }
}