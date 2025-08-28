mod modules;

use clap::{Parser, Subcommand};
use modules::discover;
use modules::info;
use modules::r#move;
use modules::persist;
use modules::scan;
use modules::vuln;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Network discovery and host scanning
    Discover {
        /// Target network range (e.g., 192.168.1.0/24)
        #[arg(short, long)]
        target: String,
    },
    /// Port scanning and service identification
    Scan {
        /// Target host (e.g., 192.168.1.1)
        #[arg(short, long)]
        target: String,

        /// Port range to scan (e.g., 1-1000 or 22,80,443)
        #[arg(
            short,
            long,
            value_name = "PORTS",
            help = "Port range to scan (e.g., 1-65535 or 22,80,443)"
        )]
        ports: Option<String>,
    },
    /// Vulnerability scanning and detection
    Vuln {
        /// Target host (e.g., 192.168.1.1)
        #[arg(short, long)]
        target: String,
    },
    /// Lateral movement tools
    Move {
        /// Target host (e.g., 192.168.1.1)
        #[arg(short, long)]
        target: String,
    },
    /// Information gathering module
    Info {
        /// Target host (e.g., 192.168.1.1)
        #[arg(short, long)]
        target: String,
    },
    /// Post-exploitation persistence functions
    Persist {
        /// Target host (e.g., 192.168.1.1)
        #[arg(short, long)]
        target: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Discover { target } => {
            println!("Performing network discovery on {}", target);
            discover::run(target);
        }
        Commands::Scan { target, ports } => {
            println!("Performing port scan on {}", target);
            scan::run(target, ports.as_deref());
        }
        Commands::Vuln { target } => {
            println!("Scanning for vulnerabilities on {}", target);
            vuln::run(target);
        }
        Commands::Move { target } => {
            println!("Performing lateral movement to {}", target);
            r#move::run(target);
        }
        Commands::Info { target } => {
            println!("Gathering information from {}", target);
            info::run(target);
        }
        Commands::Persist { target } => {
            println!("Setting up persistence on {}", target);
            persist::run(target);
        }
    }
}
