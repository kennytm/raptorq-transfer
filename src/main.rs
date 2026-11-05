use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use data_encoding::BASE64URL_NOPAD;
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::{AbortHandle, JoinSet},
    time::{Instant, MissedTickBehavior, interval},
};

const SYMBOL_SIZE: u16 = 1200;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(7);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

mod flags {
    use super::*;

    xflags::xflags! {
        cmd raptorq-transfer {
            /// Serve a single file over UDP.
            cmd sender s {
                required -b, --bind address: SocketAddr
                required -f, --file input: PathBuf
                /// Repair symbols to generate per source block (default: 32).
                optional --repair-packets count: u32
            }
            /// Receive and decode a file from a sender.
            cmd receiver r {
                required -s, --server address: SocketAddr
                required -f, --file output: PathBuf
                /// Base64url ObjectTransmissionInformation printed by the sender.
                required -c, --config oti: String
                /// Independent UDP connections feeding one decoder (default: 1).
                optional -j, --connections count: usize
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let flags = flags::RaptorqTransfer::from_env_or_exit();
    tokio::select! {
        result = async {
            match flags.subcommand {
                flags::RaptorqTransferCmd::Sender(args) => send(args).await,
                flags::RaptorqTransferCmd::Receiver(args) => receive(args).await,
            }
        } => result,
        result = tokio::signal::ctrl_c() => {
            result?;
            eprintln!("Stopped.");
            std::process::exit(0);
        }
    }
}

fn validate_oti(oti: ObjectTransmissionInformation) -> Result<()> {
    let size = u64::from(oti.symbol_size());
    let alignment = u64::from(oti.symbol_alignment());
    ensure!(
        oti.transfer_length() <= 942_574_504_275,
        "file is too large for RaptorQ"
    );
    ensure!(size > 0 && size <= 65_503, "invalid UDP symbol size");
    ensure!(
        alignment > 0 && size.is_multiple_of(alignment),
        "invalid symbol alignment"
    );
    ensure!(
        oti.sub_blocks() > 0 && u64::from(oti.sub_blocks()) <= size / alignment,
        "invalid sub-block count"
    );
    let blocks = u64::from(oti.source_blocks());
    ensure!(blocks > 0, "invalid source block count");
    let symbols = oti.transfer_length().div_ceil(size);
    ensure!(symbols == 0 || blocks <= symbols, "too many source blocks");
    ensure!(
        symbols.div_ceil(blocks) <= 56_403,
        "too many symbols per source block"
    );
    Ok(())
}

fn control_packet(kind: u8, oti: ObjectTransmissionInformation) -> Vec<u8> {
    let mut packet = b"RQT1".to_vec();
    packet.push(kind);
    packet.extend_from_slice(&oti.serialize());
    packet
}

struct Client {
    last_seen: Instant,
    task: AbortHandle,
}

async fn send(args: flags::Sender) -> Result<()> {
    let repair_packets = args.repair_packets.unwrap_or(32);
    ensure!(repair_packets <= 16_720_000, "too many repair packets");
    let socket = Arc::new(UdpSocket::bind(args.bind).await?);
    let data = tokio::fs::read(&args.file).await?;
    eprintln!("Encoding {} bytes...", data.len());
    let (oti, packets) = tokio::task::spawn_blocking(move || -> Result<_> {
        let oti = if data.is_empty() {
            ObjectTransmissionInformation::new(0, SYMBOL_SIZE, 1, 1, 8)
        } else {
            ObjectTransmissionInformation::with_defaults(data.len() as u64, SYMBOL_SIZE)
        };
        validate_oti(oti)?;
        let packets: Vec<Vec<u8>> = if data.is_empty() {
            Vec::new()
        } else {
            Encoder::new(&data, oti)
                .get_encoded_packets(repair_packets)
                .into_iter()
                .map(|packet| packet.serialize())
                .collect()
        };
        Ok((oti, packets))
    })
    .await??;
    let packets = Arc::new(packets);
    let address = socket.local_addr()?;
    let executable = std::env::current_exe()?;
    println!(
        "{} r -s 'x.x.x.x:{}' -o 'target' -c '{}'",
        executable.to_string_lossy(),
        address.port(),
        BASE64URL_NOPAD.encode(&oti.serialize()),
    );
    eprintln!(
        "Serving {} packets on {address}; press Ctrl+C to stop.",
        packets.len()
    );

    let heartbeat = control_packet(b'H', oti);
    let stop = control_packet(b'S', oti);
    let mut clients = HashMap::<SocketAddr, Client>::new();
    let mut tasks = JoinSet::new();
    let mut cleanup = interval(HEARTBEAT_INTERVAL);
    let mut buffer = [0; 64];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (length, address) = received?;
                if buffer[..length] == heartbeat && !packets.is_empty() {
                    clients.entry(address).and_modify(|client| {
                        client.last_seen = Instant::now();
                    }).or_insert_with(|| {
                        eprintln!("Client {address} connected");
                        let socket = Arc::clone(&socket);
                        let packets = Arc::clone(&packets);
                        let task = tasks.spawn(async move {
                            let result = send_packets(socket, address, packets).await;
                            (address, result)
                        });
                        Client { last_seen: Instant::now(), task }
                    });
                } else if buffer[..length] == stop
                    && let Some(client) = clients.remove(&address)
                {
                    client.task.abort();
                    eprintln!("Client {address} finished");
                }
            }
            _ = cleanup.tick() => {
                clients.retain(|address, client| {
                    if client.last_seen.elapsed() < CLIENT_TIMEOUT {
                        return true;
                    }
                    client.task.abort();
                    eprintln!("Client {address} timed out");
                    false
                });
            }
            Some(result) = tasks.join_next() => {
                match result {
                    Ok((address, result)) => {
                        if clients.get(&address).is_some_and(|client| client.task.is_finished()) {
                            clients.remove(&address);
                        }
                        if let Err(error) = result {
                            eprintln!("Client {address}: {error:#}");
                        }
                    }
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => eprintln!("Sender task: {error}"),
                }
            }
        }
    }
}

async fn send_packets(
    socket: Arc<UdpSocket>,
    address: SocketAddr,
    packets: Arc<Vec<Vec<u8>>>,
) -> Result<()> {
    let mut order: Vec<_> = (0..packets.len()).collect();
    let mut rng = fastrand::Rng::new();
    loop {
        rng.shuffle(&mut order);
        for (sent, &index) in order.iter().enumerate() {
            socket.send_to(&packets[index], address).await?;
            if sent % 64 == 0 {
                tokio::task::yield_now().await;
            }
        }
    }
}

#[derive(Default)]
struct Progress {
    received: AtomicU64,
    useful: AtomicU64,
}

async fn receive(args: flags::Receiver) -> Result<()> {
    let connections = args.connections.unwrap_or(1);
    ensure!(connections > 0, "connections must be positive");
    let encoded = BASE64URL_NOPAD
        .decode(args.config.as_bytes())
        .context("invalid base64url OTI")?;
    let encoded: [u8; 12] = encoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("OTI must contain 12 bytes"))?;
    ensure!(encoded[5] == 0, "invalid reserved OTI byte");
    let oti = ObjectTransmissionInformation::deserialize(&encoded);
    validate_oti(oti)?;
    if oti.transfer_length() == 0 {
        tokio::fs::write(&args.file, []).await?;
        eprintln!(
            "0 bytes received | 0.0 KiB/s | 100.0% — saved {}",
            args.file.display()
        );
        return Ok(());
    }

    let progress = Arc::new(Progress::default());
    let (tx, rx) = mpsc::channel(1024);
    let mut tasks = JoinSet::new();
    let mut sockets = Vec::new();
    let bind = if args.server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    for _ in 0..connections {
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        socket.connect(args.server).await?;
        tasks.spawn(send_heartbeats(Arc::clone(&socket), oti));
        tasks.spawn(receive_packets(
            Arc::clone(&socket),
            oti,
            tx.clone(),
            Arc::clone(&progress),
        ));
        sockets.push(socket);
    }
    drop(tx);
    let decode_progress = Arc::clone(&progress);
    let mut decoder = tokio::task::spawn_blocking(move || decode(oti, rx, decode_progress));
    let mut ticks = interval(HEARTBEAT_INTERVAL);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_time = Instant::now();
    let mut last_bytes = 0;
    let result = loop {
        tokio::select! {
            biased;
            result = &mut decoder => break result.context("decoder task failed").and_then(|result| result),
            Some(result) = tasks.join_next() => {
                if let Err(error) = result.context("receiver task failed").and_then(|result| result) {
                    break Err(error);
                }
            }
            _ = ticks.tick() => {
                print_progress(&progress, oti.transfer_length(), &mut last_time, &mut last_bytes, false);
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    for socket in sockets {
        if let Err(error) = socket.send(&control_packet(b'S', oti)).await {
            eprintln!("Sending stop: {error}");
        }
    }
    let data = result?;
    tokio::fs::write(&args.file, data).await?;
    print_progress(
        &progress,
        oti.transfer_length(),
        &mut last_time,
        &mut last_bytes,
        true,
    );
    eprintln!("Saved {}", args.file.display());
    Ok(())
}

async fn send_heartbeats(socket: Arc<UdpSocket>, oti: ObjectTransmissionInformation) -> Result<()> {
    let heartbeat = control_packet(b'H', oti);
    let mut ticks = interval(HEARTBEAT_INTERVAL);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticks.tick().await;
        socket.send(&heartbeat).await?;
    }
}

async fn receive_packets(
    socket: Arc<UdpSocket>,
    oti: ObjectTransmissionInformation,
    tx: mpsc::Sender<EncodingPacket>,
    progress: Arc<Progress>,
) -> Result<()> {
    let packet_size = usize::from(oti.symbol_size()) + 4;
    let mut buffer = vec![0; packet_size + 1];
    loop {
        let length = socket.recv(&mut buffer).await?;
        progress
            .received
            .fetch_add(length as u64, Ordering::Relaxed);
        if length != packet_size || buffer[0] >= oti.source_blocks() {
            eprintln!("Ignoring malformed encoding packet ({length} bytes)");
            continue;
        }
        if tx
            .send(EncodingPacket::deserialize(&buffer[..length]))
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}

fn decode(
    oti: ObjectTransmissionInformation,
    mut rx: mpsc::Receiver<EncodingPacket>,
    progress: Arc<Progress>,
) -> Result<Vec<u8>> {
    let mut decoder = Decoder::new(oti);
    let mut seen = HashSet::new();
    let symbols = oti.transfer_length().div_ceil(u64::from(oti.symbol_size()));
    let blocks = u64::from(oti.source_blocks());
    let mut received = vec![0_u64; blocks as usize];
    while let Some(packet) = rx.blocking_recv() {
        if !seen.insert(packet.payload_id().clone()) {
            continue;
        }
        let block = usize::from(packet.payload_id().source_block_number());
        received[block] += 1;
        let required = symbols / blocks + u64::from((block as u64) < symbols % blocks);
        if received[block] <= required {
            progress
                .useful
                .fetch_add(u64::from(oti.symbol_size()), Ordering::Relaxed);
        }
        if let Some(data) = decoder.decode(packet) {
            return Ok(data);
        }
    }
    bail!("all receiver connections stopped before decoding completed")
}

fn print_progress(
    progress: &Progress,
    size: u64,
    last_time: &mut Instant,
    last_bytes: &mut u64,
    complete: bool,
) {
    let now = Instant::now();
    let bytes = progress.received.load(Ordering::Relaxed);
    let speed =
        (bytes - *last_bytes) as f64 / now.duration_since(*last_time).as_secs_f64().max(0.001);
    let percent = if complete {
        100.0
    } else {
        (progress.useful.load(Ordering::Relaxed) as f64 / size as f64 * 100.0).min(99.9)
    };
    let (speed, unit) = if speed >= 1024.0 * 1024.0 {
        (speed / (1024.0 * 1024.0), "MiB/s")
    } else {
        (speed / 1024.0, "KiB/s")
    };
    eprintln!("{bytes} bytes received | {speed:.1} {unit} | ~{percent:.1}%");
    *last_time = now;
    *last_bytes = bytes;
}
