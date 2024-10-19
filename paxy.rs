use std::net::{SocketAddr, TcpStream};
use std::io::{self, Write};
use std::sync::mpsc::{self, Sender};
use std::fs::{OpenOptions, File};
use std::thread;
use std::time::Duration;
use std::sync::Arc;
use std::sync::Mutex;
use rand::Rng;
use reqwest::blocking::Client;
use serde_json::json;
use daemonize::Daemonize;
use std::process;
use std::path::Path;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use signal_hook::{consts::SIGINT, iterator::Signals};

// Global flag to indicate if the daemon should stop
static RUNNING: AtomicBool = AtomicBool::new(true);

// Function to generate random IP address
fn random_ip() -> String {
    let mut rng = rand::thread_rng();
    format!(
        "{}.{}.{}.{}",
        rng.gen_range(0..=255),
        rng.gen_range(0..=255),
        rng.gen_range(0..=255),
        rng.gen_range(0..=255)
    )
}

// Function to check if a port is open on the IP
fn is_port_open(ip: &str, port: u16, timeout: Duration) -> bool {
    let socket_addr = format!("{}:{}", ip, port);
    match socket_addr.parse::<SocketAddr>() {
        Ok(addr) => TcpStream::connect_timeout(&addr, timeout).is_ok(),
        Err(_) => false,
    }
}

// Function to check if the open IP and port is a valid proxy
fn check_proxy_http(ip: &str, port: u16) -> bool {
    let client = Client::new();
    let proxy = format!("http://{}:{}", ip, port);
    
    match client.get("http://httpbin.org/ip")
        .proxy(reqwest::Proxy::all(&proxy).unwrap())
        .timeout(Duration::from_secs(5))
        .send() {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
}

// Additional validation using HTTPS
fn check_proxy_https(ip: &str, port: u16) -> bool {
    let client = Client::new();
    let proxy = format!("https://{}:{}", ip, port);
    
    match client.get("https://httpbin.org/ip")
        .proxy(reqwest::Proxy::all(&proxy).unwrap())
        .timeout(Duration::from_secs(5))
        .send() {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
}

// Function to save working proxies
fn save_proxies(proxy: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("random_found_proxies.json")?;
    writeln!(file, "{}", proxy)?;
    Ok(())
}

// Worker function to scan and validate proxies
fn scan_random_ip(tx: Sender<String>) {
    let common_ports = vec![80, 8080, 3128, 8888, 1080]; // Common proxy ports
    let timeout = Duration::from_secs(2);
    
    let ip = random_ip();
    let port = common_ports[rand::thread_rng().gen_range(0..common_ports.len())];
    
    if is_port_open(&ip, port as u16, timeout) {
        println!("Open port found: {}:{}", ip, port);
        
        // Validate the proxy via HTTP and HTTPS
        if check_proxy_http(&ip, port as u16) || check_proxy_https(&ip, port as u16) {
            let proxy = json!({"ip": ip, "port": port});
            println!("Valid proxy found: {}", proxy);
            tx.send(proxy.to_string()).unwrap();
        }
    }
}

// Function to handle signals and stop the daemon
fn handle_signals() {
    let signals = Signals::new(&[SIGINT]).unwrap();
    for _ in signals.forever() {
        println!("Stopping daemon...");
        RUNNING.store(false, Ordering::SeqCst);
        break;
    }
}

fn run_daemon() {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));

    // Create multiple threads to scan random IPs concurrently
    for _ in 0..10 { // Adjust number of threads as needed
        let tx = Arc::clone(&tx);
        thread::spawn(move || {
            while RUNNING.load(Ordering::SeqCst) {
                scan_random_ip(tx.lock().unwrap().clone());
                thread::sleep(Duration::from_millis(500)); // Throttle to avoid overwhelming network
            }
        });
    }

    // Save valid proxies in the main thread
    for proxy in rx {
        if let Err(e) = save_proxies(&proxy) {
            eprintln!("Failed to save proxy: {}", e);
        }
    }
}

fn start_daemon() {
    let stdout = File::create("/tmp/praxyd.out").unwrap();
    let stderr = File::create("/tmp/praxyd.err").unwrap();
    let pid_file = "/tmp/praxyd.pid";

    if Path::new(pid_file).exists() {
        eprintln!("Daemon is already running.");
        process::exit(1);
    }

    let daemonize = Daemonize::new()
        .pid_file(pid_file) // Create a pid file
        .stdout(stdout) // Redirect stdout
        .stderr(stderr); // Redirect stderr

    match daemonize.start() {
        Ok(_) => {
            println!("Daemon started");
            thread::spawn(handle_signals);
            run_daemon();
        }
        Err(e) => eprintln!("Error starting daemon: {}", e),
    }
}

fn stop_daemon() {
    let pid_file = "/tmp/praxyd.pid";
    if let Ok(pid) = std::fs::read_to_string(pid_file) {
        if let Ok(pid) = pid.trim().parse::<i32>() {
            unsafe {
                libc::kill(pid, libc::SIGINT);
            }
            std::fs::remove_file(pid_file).unwrap();
            println!("Daemon stopped.");
        } else {
            eprintln!("Invalid PID.");
        }
    } else {
        eprintln!("Daemon is not running.");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "-s" {
        stop_daemon();
    } else {
        start_daemon();
    }
}
