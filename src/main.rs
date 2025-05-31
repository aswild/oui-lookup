use std::cmp::Ordering;
use std::process::ExitCode;

use clap::Parser;

mod db;
mod oui;

use oui::MacAddress;

/// Look up MAC addresses in Wireshark's OUI manuf database
#[derive(Debug, Parser)]
struct Args {
    #[arg(required = true)]
    mac: Vec<MacAddress>,
}

fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    let db = db::download_and_parse()?;
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
