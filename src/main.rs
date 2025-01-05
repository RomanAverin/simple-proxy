use bytes::{Buf, BytesMut};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TCP_PROXY_ADDR: &str = "127.0.0.1:8888";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(TCP_PROXY_ADDR).await?;
    println!("SOCKS5 proxy server listening on {TCP_PROXY_ADDR}");

    loop {
        let (client, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(client).await {
                eprintln!("Error handling client: {}", e);
            }
        });
    }
}

async fn handle_client(mut client: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = BytesMut::with_capacity(256);

    // read to the buffer
    client.read_buf(&mut buf).await?;
    // check supported version
    if buf[0] != 0x05 {
        return Err("Unsupported SOCKS version".into());
    }

    let nmethods = buf[1];
    let methods = &buf[2..2 + nmethods as usize];

    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        return Err("No acceptable authentication methods".into());
    }

    // write authentication method
    client.write_all(&[0x05, 0x00]).await?;

    // clear buffer and read
    buf.clear();
    client.read_buf(&mut buf).await?;

    if buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00 {
        return Err("Unsupported SOCKS request".into());
    }

    // Check address (IPv4, IPv6, fqdn)
    let addr_type = buf[3];
    let addr = match addr_type {
        0x01 => {
            // IPv4
            format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7])
        }
        0x03 => {
            // fqdn
            let len = buf[4] as usize;
            String::from_utf8_lossy(&buf[5..5 + len]).to_string()
        }
        0x04 => {
            // IPv6
            return Err("IPv6 not supported".into());
        }
        _ => {
            return Err("Unsupported address type".into());
        }
    };

    // Port
    let port = (&buf[buf.len() - 2..]).get_u16();

    let mut target = TcpStream::connect(format!("{}:{}", addr, port)).await?;
    let src_add = client.peer_addr().unwrap();
    println!("{src_add} -> {addr}:{port}");

    // Send response
    let response = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    client.write_all(&response).await?;

    // Split TCP connection
    let (mut client_reader, mut client_writer) = client.split();
    let (mut target_reader, mut target_writer) = target.split();

    let client_to_target = tokio::io::copy(&mut client_reader, &mut target_writer);
    let target_to_client = tokio::io::copy(&mut target_reader, &mut client_writer);

    tokio::try_join!(client_to_target, target_to_client)?;

    Ok(())
}
