use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use chrono::{DateTime, TimeZone, Utc};
use native_tls::{Certificate, TlsConnector};
use x509_parser::prelude::*;
use tokio::{time::Instant, task};

const SOCKET_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const DAYS_THRESHOLD: i64 = 30;

fn pluralize(word: &str, count: i64) -> String {
    format!("{} {}{}", count, word, if count == 1 {""} else {"s"})
}

fn format_time_remaining(duration: chrono::Duration) -> String {
    let days: i64 = duration.num_days();
    let hours: i64 = (duration.num_hours() % 24) as i64;
    let minutes: i64 = (duration.num_minutes() % 60) as i64;
    format!(
        "{} {} {}",
        pluralize("day", days),
        pluralize("hour", hours),
        pluralize("min", minutes),
    )
}

async fn get_certificate_time(host: &str) -> Result<(String, String, i64, String, String), Box<dyn std::error::Error>> {
    let host_pairs: Vec<&str> = host.split(":").collect();
    let h: &str = host_pairs[0];
    let p: &str = host_pairs[1];

    let addr: String = format!("{}:{}", h, p);

    // let sock_addr: SocketAddr = addr.to_socket_addrs()?.next().unwrap();
    let sock_addr: SocketAddr = match addr.to_socket_addrs()?.next() {
        Some(a) => a,
        None => return Err("[-] No socket address found".into()),
    };
    // let stream: TcpStream = TcpStream::connect(addr)?;
    let stream: TcpStream = TcpStream::connect_timeout(&sock_addr, SOCKET_CONNECTION_TIMEOUT)?;
    stream.set_read_timeout(Some(SOCKET_CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_CONNECTION_TIMEOUT))?;


    let ip: String = stream.peer_addr()?.to_string().split(":").next().unwrap_or("").to_string();
    let connector: TlsConnector = TlsConnector::new()?;
    let stream: native_tls::TlsStream<TcpStream> = connector.connect(h, stream)?;
    let cert: Certificate = stream.peer_certificate()?.ok_or("[-] No certificate found")?;
    let der: Vec<u8> = cert.to_der()?; // convert certificate to DER format
    let (_, parsed_cert) = X509Certificate::from_der(&der)?;
    let not_after: i64 = parsed_cert.validity().not_after.timestamp();
    let date:DateTime<Utc> = Utc.timestamp_opt(not_after, 9).single().ok_or("[-] Invalid timestamp")?;
    let time_remaining: chrono::TimeDelta = date.signed_duration_since(Utc::now());
    let day_remaining: i64 = time_remaining.num_days();
    Ok((host.to_string(), ip, day_remaining, format_time_remaining(time_remaining), date.to_string()))
}

async fn check_certificates_all(filename: &str) -> io::Result<()> {
    let file: File = File::open(filename)?;
    let reader: io::BufReader<File> = io::BufReader::new(file);
    let hostnames: Vec<String> = reader.lines().filter_map(Result::ok).collect();

    let mut log_file: Option<Arc<Mutex<fs::File>>> = match fs::File::create(format!("output/log_{}.txt", Utc::now().format("%Y-%m-%d-%H-%M-%S"))) {
        Ok(file) => Some(Arc::new(Mutex::new(file))),
        Err(err) => {
            eprintln!("[-] Failed to create log file: {}", err);
            None
        }
    };

    println!("[*] Checking {} endpoints", hostnames.len());
    write_to_file_mutex(&mut log_file, &format!("[*] Checking {} endpoints", hostnames.len()));

    // let results_sorted: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec!["".to_string(); hostnames.len()]));
    // let mut index: usize = 0;

    let mut tasks: Vec<tokio::task::JoinHandle<Option<_>>> = Vec::new();
    for host in hostnames {
        let host_clone: String = host.clone();
        // let results_sorte_clone: Arc<Mutex<Vec<String>>> = Arc::clone(&results_sorted);
        let task: tokio::task::JoinHandle<Option<_>> = tokio::spawn(async move {
            match get_certificate_time(&host_clone).await {
                Ok((host, ip, day_remaining, time_remaining_txt, date)) => {
                    let status: String = if day_remaining < DAYS_THRESHOLD {"WARN".to_string()} else {"OK".to_string()};
                    let line: String = format!("{} {} {} {} {}", host, ip ,status, time_remaining_txt, date);
                    // let mut arr: std::sync::MutexGuard<'_, Vec<String>> = results_sorte_clone.lock().unwrap();
                    // println!("{}", line);
                    // arr[index] = line.clone();
                    Some(line)
                }
                Err(err) => {
                    let line: String = format!("{} ERROR: {:?}", host, err);
                    // let mut arr: std::sync::MutexGuard<'_, Vec<String>> = results_sorte_clone.lock().unwrap();
                    // println!("{}", line);
                    // arr[index] = line.clone();
                    Some(line)
                }
            }
        });
        tasks.push(task);
        // index += 1;
    }

    let results: Vec<Result<Option<String>, task::JoinError>> = futures::future::join_all(tasks).await;
    // results as completed
    println!("{}", "#".repeat(100));
    println!("[*] Results as completed");
    for result in results {
        if let Ok(Some(res)) = result {
            println!("{}", res);
            write_to_file_mutex(&mut log_file, &format!("{}", res));
        }
    }


    // // results sorted
    // println!("{}", "#".repeat(100));
    // println!("[*] Results sorted");
    // let results_sorted: Vec<String> = match Arc::try_unwrap(results_sorted) {
    //     Ok(mutex) => match mutex.into_inner() {
    //         Ok(vec) => vec,
    //         Err(err) => {
    //             eprintln!("Failed to unlock mutex: {err}");
    //             return Ok(());
    //         }
    //     },
    //     Err(_) => {
    //         eprintln!("Failed to unwrap Arc: Multiple references exist");
    //         return Ok(());
    //     }
    // };

    // for result in results_sorted {
    //     println!("{}", result);
    //     write_to_file_mutex(&mut log_file, &format!("{}", result));
    // }
   
    Ok(())
}

fn write_to_file_mutex(file: &mut Option<Arc<Mutex<fs::File>>>, content: &str) {
    match file {
        Some(file_arc) => match file_arc.lock() {
            Ok(mut file) => match writeln!(file, "{}", content) {
                Ok(_) => {} // Successfully wrote to file
                Err(e) => eprintln!("[*] Failed to write to file: {}", e),
            },
            Err(e) => eprintln!("[*] Failed to acquire file lock: {}", e),
        },
        None => eprintln!("[*] File not available for writing."),
    }
}

#[tokio::main]
async fn main() {
    let start: Instant = Instant::now();
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        let filename: &String = &args[1];
        if let Err(err) = check_certificates_all(filename).await {
            eprintln!("[-] Error: {}", err);
        }
    } else {
        println!("[*] Usage: {} [hostnames_file]", args[0]);
    }
    println!("\n[*] Done in {:.2?}", start.elapsed());
}
