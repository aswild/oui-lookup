use std::cmp::Ordering;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

mod db;
mod oui;

use oui::MacAddress;

/// Look up MAC addresses in Wireshark's OUI manuf database
#[derive(Debug, Parser)]
struct Args {
    #[command(flatten)]
    cache_args: CacheArgs,

    #[arg(required = true)]
    mac: Vec<MacAddress>,
}

#[derive(Debug, clap::Args)]
struct CacheArgs {
    /// Do not read or write a cache file
    #[arg(short, long)]
    no_cache: bool,

    /// Force re-downloading the database (updating the cache on disk afterwards)
    #[arg(short, long)]
    force: bool,

    /// Custom cache file location
    ///
    /// The default is in a platform-dependent default location
    #[arg(short, long, conflicts_with = "no_cache")]
    cache_file: Option<PathBuf>,
}

fn run() -> anyhow::Result<()> {
    serif::Config::new()
        .with_default(serif::tracing::Level::WARN)
        .with_timestamp(serif::TimeFormat::none())
        .init();
    let args = Args::parse();

    let db = db::load(&args.cache_args)?;
    for mac in args.mac.iter().copied() {
        let index = db.binary_search_by(|oui| {
            if oui.mac_prefix.matches(mac) {
                return Ordering::Equal;
            }
            let prefix_mac = oui.mac();
            debug_assert!(prefix_mac != mac);
            prefix_mac.cmp(&mac)
        });

        if let Ok(i) = index {
            let oui = &db[i];
            println!("{mac} - {} - {}", oui.mac_prefix, oui.long_name);
        } else {
            println!("{mac} - no matching OUI found");
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("Error: {err:#}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
