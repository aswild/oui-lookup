use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Context as _;
use flate2::bufread::GzDecoder;
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use reqwest::header::{self, AsHeaderName};
use serde::{Deserialize, Serialize};
use serif::macros::*;

use crate::CacheArgs;
use crate::oui::Oui;

const DB_URL: &str = "https://www.wireshark.org/download/automated/data/manuf.gz";

static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(Client::new);

static DEFAULT_CACHE: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    let mut path = dirs::cache_dir()?;
    path.push("oui-lookup");
    path.push("manuf.db");
    Some(path)
});

#[derive(Debug, Serialize, Deserialize)]
pub struct Cache {
    last_modified: Option<String>,
    etag: Option<String>,
    db: Vec<Oui>,
}

impl Cache {
    fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        debug!("loading cache file {}", path.display());
        match std::fs::read(path) {
            Ok(bytes) => {
                Ok(Some(postcard::from_bytes(&bytes).context("failed to parse cache file")?))
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).context(format!("failed to open {} for reading", path.display())),
        }
    }

    fn save(&self, path: &Path) -> anyhow::Result<()> {
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir).context("failed to create cache directory")?;
        let mut fp = File::create(path).context("failed to open cache file for writing")?;
        match postcard::to_io(self, &mut fp) {
            Ok(_) => Ok(()),
            Err(err) => {
                // delete the incomplete file
                drop(fp);
                let _ = std::fs::remove_file(path);
                Err(err).context("failed writing cache file")
            }
        }
    }

    fn up_to_date(&self) -> bool {
        let mut req = HTTP_CLIENT.head(DB_URL);
        if let Some(ref val) = self.last_modified {
            req = req.header(header::IF_MODIFIED_SINCE, val);
        }
        if let Some(ref val) = self.etag {
            req = req.header(header::IF_NONE_MATCH, val);
        }

        let resp = match req.send() {
            Ok(resp) => resp,
            Err(err) => {
                warn!("failed to send HEAD request: {err}");
                return false;
            }
        };

        resp.status() == StatusCode::NOT_MODIFIED
    }
}

pub fn load(args: &CacheArgs) -> anyhow::Result<Vec<Oui>> {
    let cache_path = args.cache_file.as_deref().or_else(|| DEFAULT_CACHE.as_deref());
    let skip_cache = if args.no_cache {
        debug!("Arg --no-cache specified, skipping all disk cache checks");
        true
    } else if cache_path.is_none() {
        warn!("Unable to determine default cache file path");
        true
    } else {
        false
    };

    if skip_cache {
        let cache = download_fresh()?;
        return Ok(cache.db);
    }

    let Some(cache_path) = cache_path else { unreachable!() };
    let mut save_cache = true;
    let cache = if args.force {
        debug!("Arg --force specified, downloading before checking cache");
        download_fresh()?
    } else {
        match Cache::load(cache_path) {
            Ok(Some(cache)) => {
                if cache.up_to_date() {
                    info!("cache is up to date");
                    save_cache = false;
                    cache
                } else {
                    info!("cache is stale, re-downloading");
                    download_fresh()?
                }
            }
            Ok(None) => {
                debug!("cache file {} doesn't exist", cache_path.display());
                download_fresh()?
            }
            Err(err) => {
                warn!("error loading cache: {err:#}");
                download_fresh()?
            }
        }
    };

    if save_cache {
        if let Err(err) = cache.save(cache_path) {
            warn!("failed to save cache file: {err:#}");
        }
    }

    Ok(cache.db)
}

fn download_fresh() -> anyhow::Result<Cache> {
    // request
    let resp = HTTP_CLIENT.get(DB_URL).send().context("failed to send web request")?;

    // response headers
    if !resp.status().is_success() {
        anyhow::bail!("web request to fetch database failed: {}", resp.status());
    }
    let last_modified = resp.header_string(header::LAST_MODIFIED);
    let etag = resp.header_string(header::ETAG);

    // response body
    let gz_data = resp.bytes().context("failed to get web request response body")?;

    // decompress
    let mut data = Vec::with_capacity(gz_data.len() * 4);
    GzDecoder::new(&*gz_data).read_to_end(&mut data).context("failed to decode gzipped data")?;

    // parse
    let str_data = String::from_utf8(data).context("OUI db data is not UTF-8")?;
    let mut ouis = str_data.lines().filter_map(Oui::from_manuf).collect::<Vec<_>>();
    ouis.sort();

    Ok(Cache { last_modified, etag, db: ouis })
}

/// It's surprisingly annoyingly verbose to get a header value as a string
trait ResponseExt {
    fn header_string(&self, name: impl AsHeaderName) -> Option<String>;
}

impl ResponseExt for Response {
    fn header_string(&self, name: impl AsHeaderName) -> Option<String> {
        self.headers().get(name).and_then(|v| v.to_str().ok()).map(String::from)
    }
}
