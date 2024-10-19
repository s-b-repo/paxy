Praxyd - Proxy Scanning Daemon

Praxyd is a lightweight Rust-based daemon that scans random IP addresses for open proxies and validates them through multiple methods. It supports HTTP and HTTPS proxy validation, runs as a background process, and can be controlled via command-line options.
Features

    Random IP Scanning: Generates random IP addresses and scans common proxy ports.
    Multiple Proxy Validation Methods: Validates proxies using both HTTP and HTTPS.
    Daemonized Process: Runs in the background as a system daemon.
    Concurrent Scanning: Scans multiple IPs concurrently using multithreading for higher efficiency.
    Graceful Shutdown: Can be stopped via a simple command, ensuring clean shutdown.
    Proxy Logging: Saves valid proxies to a JSON file for future use.

Installation
Prerequisites

    Rust: Ensure that you have Rust installed. If not, you can install it using rustup.

    

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

    Git: Clone the repository to your local machine.

Steps

    Clone the repository:

    

git clone https://github.com/s-b-repo/paxy.git

Navigate into the project directory:



cd praxyd

Build the project:



cargo build --release

Install the binary (optional but recommended):



    cargo install --path .

Usage
Starting the Daemon

To start the praxyd daemon, simply run:



./praxyd

This will start the proxy scanner in the background. It will scan random IP addresses for open proxy ports and validate them.
Stopping the Daemon

To stop the daemon gracefully, use:



./praxyd -s

This command will send a stop signal (SIGINT) to the running daemon and remove its PID file.
Viewing Logs

The daemon's logs, including both standard output and errors, can be found at:

    /tmp/praxyd.out: Standard output log.
    /tmp/praxyd.err: Error log.

Saved Proxies

Valid proxies are saved to random_found_proxies.json. Each proxy entry includes the IP address and port, in JSON format:



{
  "ip": "192.168.1.100",
  "port": 8080
}

Configuration
Common Proxy Ports

By default, the following common proxy ports are scanned: 80, 8080, 3128, 8888, and 1080. You can modify this list directly in the source code under the common_ports variable if you need to scan specific ports.
Scan Interval

The daemon continuously scans IPs in multiple threads. The sleep interval between scans is set to 500ms to prevent overwhelming the network.
Contributing

Contributions are welcome! Feel free to submit a pull request, report issues, or request new features.

    Fork the repository
    Create your feature branch (git checkout -b feature/AmazingFeature)
    Commit your changes (git commit -m 'Add some AmazingFeature')
    Push to the branch (git push origin feature/AmazingFeature)
    Open a pull request

Acknowledgments

    Rust Language
    daemonize for easy daemonization.
    signal-hook for signal handling in Rust.
    reqwest for HTTP client functionality.
    The open-source community for contributing to tools like httpbin.org for proxy validation.
