use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimDatabaseConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[derive(Clone, Copy)]
enum Flavor {
    Mysql,
    Postgresql,
}

struct Context {
    rule_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    config: SimDatabaseConfig,
    flavor: Flavor,
}

fn report(ctx: &Context, peer: SocketAddr, event_type: &str, summary: String, payload: &[u8]) {
    report_sim_log_async(
        ctx.callback_url.clone(),
        SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: peer.ip().to_string(),
            client_port: peer.port(),
            server_port: ctx.port,
            event_type: event_type.to_string(),
            detail_summary: summary,
            payload_hex: (!payload.is_empty())
                .then(|| encode_hex(&payload[..payload.len().min(512)])),
        },
    );
}

fn mysql_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut packet = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, sequence];
    packet.extend_from_slice(payload);
    packet
}

async fn handle_mysql(
    ctx: Arc<Context>,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    report(
        &ctx,
        peer,
        "connection",
        "MySQL client connected".to_string(),
        &[],
    );
    let version = ctx
        .config
        .server_version
        .as_deref()
        .unwrap_or("8.0.36-seclab");
    let mut handshake = vec![0x0a];
    handshake.extend_from_slice(version.as_bytes());
    handshake.push(0);
    handshake.extend_from_slice(&1_u32.to_le_bytes());
    handshake.extend_from_slice(b"seclab01\0");
    handshake.extend_from_slice(&0xffff_u16.to_le_bytes());
    handshake.push(0x21);
    handshake.extend_from_slice(&0x0002_u16.to_le_bytes());
    handshake.extend_from_slice(&0xffff_u16.to_le_bytes());
    handshake.push(21);
    handshake.extend_from_slice(&[0; 10]);
    handshake.extend_from_slice(b"simulation12\0");
    handshake.extend_from_slice(b"mysql_native_password\0");
    stream.write_all(&mysql_packet(0, &handshake)).await?;
    let mut buffer = vec![0; 4096];
    let read = stream.read(&mut buffer).await?;
    if read > 0 {
        report(
            &ctx,
            peer,
            "auth_attempt",
            "MySQL authentication packet received".to_string(),
            &buffer[..read],
        );
        let error = b"#HY000Access denied by SecLab simulation";
        let mut payload = vec![0xff, 0x15, 0x04];
        payload.extend_from_slice(error);
        stream.write_all(&mysql_packet(2, &payload)).await?;
    }
    Ok(())
}

async fn handle_postgresql(
    ctx: Arc<Context>,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    report(
        &ctx,
        peer,
        "connection",
        "PostgreSQL client connected".to_string(),
        &[],
    );
    let mut buffer = vec![0; 8192];
    let mut read = stream.read(&mut buffer).await?;
    if read == 8 && buffer[4..8] == [4, 210, 22, 47] {
        stream.write_all(b"N").await?;
        read = stream.read(&mut buffer).await?;
    }
    if read > 0 {
        report(
            &ctx,
            peer,
            "auth_attempt",
            "PostgreSQL startup packet received".to_string(),
            &buffer[..read],
        );
        stream.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3]).await?;
        let password_read = stream.read(&mut buffer).await?;
        if password_read > 0 {
            report(
                &ctx,
                peer,
                "auth_attempt",
                "PostgreSQL password message received".to_string(),
                &buffer[..password_read],
            );
        }
        let message = b"SERROR\0C28P01\0Mpassword authentication failed\0\0";
        let mut response = vec![b'E'];
        response.extend_from_slice(&((message.len() + 4) as u32).to_be_bytes());
        response.extend_from_slice(message);
        stream.write_all(&response).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimDatabaseConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
    flavor: Flavor,
) -> anyhow::Result<()> {
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "database simulation started");
    let ctx = Arc::new(Context {
        rule_id,
        callback_url,
        node_id,
        port,
        config,
        flavor,
    });
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = result?;
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    let result = match ctx.flavor {
                        Flavor::Mysql => handle_mysql(Arc::clone(&ctx), stream, peer).await,
                        Flavor::Postgresql => handle_postgresql(Arc::clone(&ctx), stream, peer).await,
                    };
                    if let Err(error) = result { tracing::debug!(%peer, %error, "database connection ended with error"); }
                });
            }
            _ = &mut shutdown_rx => break,
        }
    }
    Ok(())
}

macro_rules! database_start {
    ($name:ident, $flavor:expr) => {
        #[allow(clippy::too_many_arguments)]
        pub async fn $name(
            rule_id: String,
            rule_name: Option<String>,
            port: u16,
            callback_url: String,
            node_id: String,
            config: SimDatabaseConfig,
            listener: TcpListener,
            shutdown_rx: oneshot::Receiver<()>,
        ) -> anyhow::Result<()> {
            run(
                rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                config,
                listener,
                shutdown_rx,
                $flavor,
            )
            .await
        }
    };
}
database_start!(start_mysql_simulation, Flavor::Mysql);
database_start!(start_postgresql_simulation, Flavor::Postgresql);
