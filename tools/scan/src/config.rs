//! Strict config and inventory file parsing (unknown keys are an error;
//! all config keys optional, defaults apply). Files are local trusted input
//! but still parsed with the capped strict JSON parser.

use crate::json::{self, Value};
use crate::sanitize::sanitize;

#[derive(Clone, Debug)]
pub struct FeedToggles {
    pub kev: bool,
    pub osv: bool,
    pub github: bool,
    pub epss: bool,
    pub nvd: bool,
}

impl Default for FeedToggles {
    fn default() -> Self {
        FeedToggles { kev: true, osv: true, github: true, epss: true, nvd: false }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub inventory: String,
    pub interval_secs: u64,
    pub max_runs: u64,
    pub out_dir: String,
    pub git_remote: String,
    pub http_timeout_secs: u64,
    pub max_body_bytes: usize,
    pub epss_threshold: f64,
    pub kev_recent_days: u64,
    pub feeds: FeedToggles,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            inventory: "tools/scan/inventory.json".to_string(),
            interval_secs: 3600,
            max_runs: 0,
            out_dir: "tools/scan/out".to_string(),
            git_remote: "origin".to_string(),
            http_timeout_secs: 60,
            max_body_bytes: 8 * 1024 * 1024,
            epss_threshold: 0.5,
            kev_recent_days: 30,
            feeds: FeedToggles::default(),
        }
    }
}

fn get_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("config key {:?} must be a string", key))
}

fn get_u64(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("config key {:?} must be a non-negative integer", key))
}

fn get_f64(v: &Value, key: &str) -> Result<f64, String> {
    v.get(key)
        .and_then(|x| x.as_f64())
        .ok_or_else(|| format!("config key {:?} must be a number", key))
}

/// Parse config JSON strictly. Unknown keys are an error.
pub fn parse_config(text: &str) -> Result<Config, String> {
    let v = json::parse(text).map_err(|e| format!("config is not valid JSON: {}", e))?;
    let obj = v.as_obj().ok_or_else(|| "config must be a JSON object".to_string())?;
    let mut cfg = Config::default();
    for (k, val) in obj {
        match k.as_str() {
            "inventory" => cfg.inventory = get_str(&v, k)?,
            "interval_secs" => cfg.interval_secs = get_u64(&v, k)?,
            "max_runs" => cfg.max_runs = get_u64(&v, k)?,
            "out_dir" => cfg.out_dir = get_str(&v, k)?,
            "git_remote" => cfg.git_remote = get_str(&v, k)?,
            "http_timeout_secs" => cfg.http_timeout_secs = get_u64(&v, k)?,
            "max_body_bytes" => {
                let n = get_u64(&v, k)?;
                cfg.max_body_bytes = n as usize;
            }
            "epss_threshold" => {
                let f = get_f64(&v, k)?;
                if !(0.0..=1.0).contains(&f) {
                    return Err("epss_threshold must be within [0, 1]".to_string());
                }
                cfg.epss_threshold = f;
            }
            "kev_recent_days" => cfg.kev_recent_days = get_u64(&v, k)?,
            "feeds" => {
                let fobj = val.as_obj().ok_or_else(|| "config key \"feeds\" must be an object".to_string())?;
                for (fk, fv) in fobj {
                    let b = fv.as_bool().ok_or_else(|| format!("feeds.{} must be a boolean", fk))?;
                    match fk.as_str() {
                        "kev" => cfg.feeds.kev = b,
                        "osv" => cfg.feeds.osv = b,
                        "github" => cfg.feeds.github = b,
                        "epss" => cfg.feeds.epss = b,
                        "nvd" => cfg.feeds.nvd = b,
                        other => return Err(format!("unknown feeds key {:?}", other)),
                    }
                }
            }
            other => return Err(format!("unknown config key {:?}", other)),
        }
    }
    Ok(cfg)
}

#[derive(Clone, Debug, PartialEq)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Product {
    pub vendor: String,
    pub product: String,
}

#[derive(Clone, Debug, Default)]
pub struct Inventory {
    pub packages: Vec<Package>,
    pub products: Vec<Product>,
    pub cves: Vec<String>,
}

/// Parse the inventory file strictly.
pub fn parse_inventory(text: &str) -> Result<Inventory, String> {
    let v = json::parse(text).map_err(|e| format!("inventory is not valid JSON: {}", e))?;
    let obj = v.as_obj().ok_or_else(|| "inventory must be a JSON object".to_string())?;
    let mut inv = Inventory::default();
    for (k, val) in obj {
        match k.as_str() {
            "packages" => {
                let arr = val.as_array().ok_or_else(|| "inventory.packages must be an array".to_string())?;
                for item in arr {
                    let eco = item.get("ecosystem").and_then(|x| x.as_str()).ok_or("package missing ecosystem")?;
                    let name = item.get("name").and_then(|x| x.as_str()).ok_or("package missing name")?;
                    let ver = item.get("version").and_then(|x| x.as_str()).ok_or("package missing version")?;
                    inv.packages.push(Package {
                        ecosystem: sanitize(eco),
                        name: sanitize(name),
                        version: sanitize(ver),
                    });
                }
            }
            "products" => {
                let arr = val.as_array().ok_or_else(|| "inventory.products must be an array".to_string())?;
                for item in arr {
                    let vendor = item.get("vendor").and_then(|x| x.as_str()).ok_or("product missing vendor")?;
                    let prod = item.get("product").and_then(|x| x.as_str()).ok_or("product missing product")?;
                    inv.products.push(Product { vendor: sanitize(vendor), product: sanitize(prod) });
                }
            }
            "cves" => {
                let arr = val.as_array().ok_or_else(|| "inventory.cves must be an array".to_string())?;
                for item in arr {
                    let c = item.as_str().ok_or("inventory.cves entries must be strings")?;
                    inv.cves.push(sanitize(c));
                }
            }
            other => return Err(format!("unknown inventory key {:?}", other)),
        }
    }
    Ok(inv)
}

/// Load a config file from disk; empty path -> defaults.
pub fn load_config(path: &str) -> Result<Config, String> {
    if path.is_empty() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read config {:?}: {}", path, e))?;
    parse_config(&text)
}

/// Load the inventory, from `override_path` if given else `config.inventory`.
pub fn load_inventory(cfg: &Config, override_path: Option<&str>) -> Result<Inventory, String> {
    let path = override_path.unwrap_or(&cfg.inventory);
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read inventory {:?}: {}", path, e))?;
    parse_inventory(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_strict_keys() {
        let cfg = parse_config("{}").unwrap();
        assert_eq!(cfg.interval_secs, 3600);
        assert_eq!(cfg.max_body_bytes, 8 * 1024 * 1024);
        assert!(!cfg.feeds.nvd);
        assert!(cfg.feeds.kev);
        assert!(parse_config(r#"{"bogus": 1}"#).is_err());
        assert!(parse_config(r#"{"feeds": {"bogus": true}}"#).is_err());
        assert!(parse_config(r#"{"epss_threshold": 2}"#).is_err());
        assert!(parse_config(r#"{"interval_secs": "soon"}"#).is_err());
        let cfg = parse_config(r#"{"interval_secs": 5, "feeds": {"nvd": true}, "epss_threshold": 0.7}"#).unwrap();
        assert_eq!(cfg.interval_secs, 5);
        assert!(cfg.feeds.nvd);
        assert!((cfg.epss_threshold - 0.7).abs() < 1e-9);
    }

    #[test]
    fn inventory_parse() {
        let inv = parse_inventory(
            r#"{"packages": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
                "products": [{"vendor": "Microsoft", "product": "Exchange Server"}],
                "cves": ["CVE-2021-44228"]}"#,
        )
        .unwrap();
        assert_eq!(inv.packages.len(), 1);
        assert_eq!(inv.packages[0].name, "lodash");
        assert_eq!(inv.products[0].vendor, "Microsoft");
        assert_eq!(inv.cves, vec!["CVE-2021-44228".to_string()]);
        assert!(parse_inventory(r#"{"nope": []}"#).is_err());
        assert!(parse_inventory(r#"{"packages": [{"ecosystem": "npm"}]}"#).is_err());
        assert!(parse_inventory("not json").is_err());
    }
}
