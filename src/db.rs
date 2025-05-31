use std::io::Read;

use anyhow::Context as _;
use flate2::bufread::GzDecoder;
use reqwest::blocking::Client;

use crate::oui::Oui;

const DB_URL: &str = "https://www.wireshark.org/download/automated/data/manuf.gz";

pub fn download_db() -> anyhow::Result<Vec<u8>> {
    let client = Client::new();
    let resp = client
        .get(DB_URL)
        .send()
        .context("failed to send web request")?;
    if !resp.status().is_success() {
        anyhow::bail!("web request to fetch database failed: {}", resp.status());
    }

    let data = resp
        .bytes()
        .context("failed to get web request response body")?;
    let mut dec_data = Vec::with_capacity(data.len() * 4);
    GzDecoder::new(&*data)
        .read_to_end(&mut dec_data)
        .context("failed to decode gzipped data")?;
    Ok(dec_data)
}

pub fn download_and_parse() -> anyhow::Result<Vec<Oui>> {
    let db = String::from_utf8(download_db()?).context("OUI db data is not UTF-8")?;
    let mut ouis = db.lines().filter_map(Oui::from_manuf).collect::<Vec<_>>();
    ouis.sort();
    Ok(ouis)
}
