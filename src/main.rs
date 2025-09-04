mod modules;

use clap::{Parser, Subcommand};
use modules::host;
use modules::info;
use modules::persist;
use modules::scan;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Host {
        #[arg(
            short,
            long,
            value_name = "NETWORK",
            help = "Target network to scan (e.g., 192.168.1.0/24)"
        )]
        target: String,

        #[arg(
            short = 's',
            long = "scan-type",
            value_name = "SCAN_TYPE",
            default_value = "icmp",
            help = "Scan type: icmp or tcp"
        )]
        scan_type: String,
    },
    Discover {
        #[arg(short, long)]
        target: String,
    },
    Scan {
        #[arg(short, long)]
        target: String,

        #[arg(
            short,
            long,
            value_name = "PORTS",
            help = "Port range to scan (e.g., 1-65535 or 22,80,443)"
        )]
        ports: Option<String>,
    },
    Info {
        #[arg(short, long)]
        target: String,
    },
    Persist {
        #[arg(short, long)]
        target: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Host { target, scan_type } => {
            println!(
                "Performing host discovery on {} with {} scan",
                target, scan_type
            );
            let result = host::discover_hosts(target, scan_type);
            println!("{}", result);
        }
        Commands::Discover { target } => {
            println!("Performing network discovery on {}", target);
            // discover::run(target);
        }
        Commands::Scan { target, ports } => {
            println!("Performing port scan on {}", target);
            scan::run(target, ports.as_deref());
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
